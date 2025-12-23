/* akvcam, virtual camera for Linux.
 * Copyright (C) 2018  Gonzalo Exequiel Pedone
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <media/v4l2-common.h>
#include <media/videobuf2-vmalloc.h>

#include "buffers.h"
#include "device.h"
#include "format.h"
#include "frame.h"
#include "log.h"
#include "debug_control.h"

#define META_SIZE 16  // metadata 大小：tv_sec (8) + tv_usec (8)

#define AKVCAM_BUFFERS_MIN 2

typedef struct {
    struct vb2_v4l2_buffer vb;
    struct list_head list;
    u64 metadata_timestamp_ns;  // 从 metadata 解析的时间戳（纳秒），0 表示未设置
} akvcam_buffers_buffer, *akvcam_buffers_buffer_t;

static const struct vb2_ops akvcam_akvcam_buffers_queue_ops;

struct akvcam_buffers
{
    struct kref ref;
    struct list_head buffers;
    struct vb2_queue queue;
    struct mutex buffers_mutex;
    struct mutex frames_mutex;
    akvcam_format_t format;
    akvcam_signal_callback(buffers, streaming_started);
    akvcam_signal_callback(buffers, streaming_stopped);
    enum v4l2_buf_type type;
    AKVCAM_RW_MODE rw_mode;
    __u32 sequence;
    u64 last_frame_timestamp_ns;  // 最后读取的 frame 的时间戳（用于传递到 capture device）
};

akvcam_signal_define(buffers, streaming_started)
akvcam_signal_define(buffers, streaming_stopped)

enum vb2_io_modes akvcam_buffers_io_modes_from_device_type(enum v4l2_buf_type type,
                                                           AKVCAM_RW_MODE rw_mode);
int akvcam_buffers_queue_setup(struct vb2_queue *queue,
                               unsigned int *num_buffers,
                               unsigned int *num_planes,
                               unsigned int sizes[],
                               struct device *alloc_devs[]);
int akvcam_buffers_buffer_prepare(struct vb2_buffer *buffer);
void akvcam_buffers_buffer_queue(struct vb2_buffer *buffer);
int akvcam_buffers_start_streaming(struct vb2_queue *queue, unsigned int count);
void akvcam_buffers_stop_streaming(struct vb2_queue *queue);

akvcam_buffers_t akvcam_buffers_new(AKVCAM_RW_MODE rw_mode,
                                    enum v4l2_buf_type type)
{
    akvcam_buffers_t self = kzalloc(sizeof(struct akvcam_buffers), GFP_KERNEL);

    kref_init(&self->ref);
    INIT_LIST_HEAD(&self->buffers);
    mutex_init(&self->buffers_mutex);
    mutex_init(&self->frames_mutex);
    self->rw_mode = rw_mode;
    self->type = type;
    self->format = akvcam_format_new(0, 0, 0, NULL);
    self->queue.type = type;
    self->queue.io_modes =
            akvcam_buffers_io_modes_from_device_type(self->type,
                                                     self->rw_mode);
    self->queue.drv_priv = self;
    self->queue.lock = &self->buffers_mutex;
    self->queue.buf_struct_size = sizeof(akvcam_buffers_buffer);
    self->queue.mem_ops = &vb2_vmalloc_memops;
    self->queue.ops = &akvcam_akvcam_buffers_queue_ops;
    self->queue.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;

    akvcam_buffers_set_count(self, AKVCAM_BUFFERS_MIN);

    return self;
}

static void akvcam_buffers_free(struct kref *ref)
{
    akvcam_buffers_t self = container_of(ref, struct akvcam_buffers, ref);
    akvcam_format_delete(self->format);
    kfree(self);
}

void akvcam_buffers_delete(akvcam_buffers_t self)
{
    if (self)
        kref_put(&self->ref, akvcam_buffers_free);
}

akvcam_buffers_t akvcam_buffers_ref(akvcam_buffers_t self)
{
    if (self)
        kref_get(&self->ref);

    return self;
}

akvcam_format_t akvcam_buffers_format(akvcam_buffers_ct self)
{
    return akvcam_format_new_copy(self->format);
}

void akvcam_buffers_set_format(akvcam_buffers_t self, akvcam_format_ct format)
{
    akvcam_format_copy(self->format, format);
}

size_t akvcam_buffers_count(akvcam_buffers_ct self)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION( 6, 8, 0)
    return self->queue.min_buffers_needed;
#else
    return self->queue.min_queued_buffers;
#endif
}

void akvcam_buffers_set_count(akvcam_buffers_t self, size_t nbuffers)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION( 6, 8, 0)
    self->queue.min_buffers_needed = nbuffers;
#else
    self->queue.min_queued_buffers = nbuffers;
#endif
}

akvcam_frame_t akvcam_buffers_read_frame(akvcam_buffers_t self)
{
    akvcam_frame_t frame;
    akvcam_buffers_buffer_t buf;
    size_t i;

    akpr_function();

    if (mutex_lock_interruptible(&self->frames_mutex))
        return NULL;

    if (list_empty(&self->buffers)) {
        mutex_unlock(&self->frames_mutex);

        return NULL;
    }

    buf = list_entry(self->buffers.next, akvcam_buffers_buffer, list);
    list_del(&buf->list);
    
    // 如果 buffer 有从 metadata 解析的时间戳，使用它；否则使用当前时间
    if (buf->metadata_timestamp_ns != 0) {
        buf->vb.vb2_buf.timestamp = buf->metadata_timestamp_ns;
        // 设置时间戳标志
        buf->vb.flags |= V4L2_BUF_FLAG_TIMESTAMP_COPY;
        buf->vb.flags &= ~V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
        
        // 保存时间戳到 buffers 结构，用于传递到 capture device
        self->last_frame_timestamp_ns = buf->metadata_timestamp_ns;
        
        // 记录设置时间戳的日志
        u64 timestamp_us = buf->metadata_timestamp_ns / 1000;
        u64 now_ns = ktime_get_ns();
        u64 now_us = now_ns / 1000;
        log_point("AKVCAM set buffer timestamp", timestamp_us, now_us);
    } else {
        buf->vb.vb2_buf.timestamp = ktime_get_ns();
        self->last_frame_timestamp_ns = 0;  // 清除保存的时间戳
    }
    
    buf->vb.field = V4L2_FIELD_NONE;
    buf->vb.sequence = self->sequence++;
    mutex_unlock(&self->frames_mutex);

    frame = akvcam_frame_new(self->format, NULL, 0);

    for (i = 0; i < buf->vb.vb2_buf.num_planes; i++) {
        memcpy(akvcam_frame_plane_data(frame, i),
               vb2_plane_vaddr(&buf->vb.vb2_buf, i),
               akvcam_format_plane_size(self->format, i));
    }

    vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_DONE);

    return frame;
}

int akvcam_buffers_write_frame(akvcam_buffers_t self, akvcam_frame_t frame)
{
    akvcam_buffers_buffer_t buf;
    size_t i;
    int result;

    akpr_function();
    result = mutex_lock_interruptible(&self->frames_mutex);

    if (result)
        return result;

    if (list_empty(&self->buffers)) {
        mutex_unlock(&self->frames_mutex);

        return -EAGAIN;
    }

    buf = list_entry(self->buffers.next, akvcam_buffers_buffer, list);
    list_del(&buf->list);
    
    // 对于 capture device，从 device 的 frame_timestamp_ns 获取时间戳
    // 这个时间戳是从 output device 传递过来的
    // 注意：我们需要从 device 获取时间戳，但这里没有直接访问 device 的方式
    // 所以我们需要通过其他方式传递时间戳
    // 实际上，时间戳应该在 device 的 frame_timestamp_ns 中
    // 但这里我们无法直接访问 device，所以暂时使用 buffer 的 metadata_timestamp_ns
    // 或者使用保存的 last_frame_timestamp_ns
    if (buf->metadata_timestamp_ns != 0) {
        buf->vb.vb2_buf.timestamp = buf->metadata_timestamp_ns;
        buf->vb.flags |= V4L2_BUF_FLAG_TIMESTAMP_COPY;
        buf->vb.flags &= ~V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
    } else if (self->last_frame_timestamp_ns != 0) {
        // 使用保存的时间戳
        buf->vb.vb2_buf.timestamp = self->last_frame_timestamp_ns;
        buf->vb.flags |= V4L2_BUF_FLAG_TIMESTAMP_COPY;
        buf->vb.flags &= ~V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
    } else {
        buf->vb.vb2_buf.timestamp = ktime_get_ns();
    }
    
    buf->vb.field = V4L2_FIELD_NONE;
    buf->vb.sequence = self->sequence++;
    mutex_unlock(&self->frames_mutex);

    for (i = 0; i < buf->vb.vb2_buf.num_planes; i++) {
        memcpy(vb2_plane_vaddr(&buf->vb.vb2_buf, i),
               akvcam_frame_plane_data(frame, i),
               vb2_plane_size(&buf->vb.vb2_buf, i));
    }

    vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_DONE);

    return 0;
}

struct vb2_queue *akvcam_buffers_vb2_queue(akvcam_buffers_t self)
{
    return &self->queue;
}

enum vb2_io_modes akvcam_buffers_io_modes_from_device_type(enum v4l2_buf_type type,
                                                           AKVCAM_RW_MODE rw_mode)
{
    enum vb2_io_modes io_modes = 0;

    if (rw_mode & AKVCAM_RW_MODE_READWRITE) {
        if (akvcam_device_type_from_v4l2(type) == AKVCAM_DEVICE_TYPE_CAPTURE)
            io_modes |= VB2_READ;
        else
            io_modes |= VB2_WRITE;
    }

    if (rw_mode & AKVCAM_RW_MODE_MMAP)
        io_modes |= VB2_MMAP;

    if (rw_mode & AKVCAM_RW_MODE_USERPTR)
        io_modes |= VB2_USERPTR;

    if (rw_mode & AKVCAM_RW_MODE_DMABUF)
        io_modes |= VB2_DMABUF;

    return io_modes;
}

int akvcam_buffers_queue_setup(struct vb2_queue *queue,
                               unsigned int *num_buffers,
                               unsigned int *num_planes,
                               unsigned int sizes[],
                               struct device *alloc_devs[])
{
    akvcam_buffers_t self = vb2_get_drv_priv(queue);
    size_t i;
    UNUSED(alloc_devs);
    akpr_function();

    if (*num_buffers < 1)
        *num_buffers = 1;

    if (*num_planes > 0) {
        if (*num_planes < akvcam_format_planes(self->format))
            return -EINVAL;

        for (i = 0; i < *num_planes; i++)
            if (sizes[i] < akvcam_format_plane_size(self->format, i))
                return -EINVAL;

        return 0;
    }

    *num_planes = akvcam_format_planes(self->format);

    for (i = 0; i < *num_planes; i++)
        sizes[i] = akvcam_format_plane_size(self->format, i);

    return 0;
}

int akvcam_buffers_buffer_prepare(struct vb2_buffer *buffer)
{
    akvcam_buffers_t self = vb2_get_drv_priv(buffer->vb2_queue);
    struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(buffer);
    size_t i;

    akpr_function();

    for (i = 0; i < buffer->num_planes; i++) {
        size_t plane_size = akvcam_format_plane_size(self->format, i);

        if (vb2_plane_size(buffer, i) < plane_size)
            return -EINVAL;
        else
            // 注意：对于 WRITE 模式，payload 会在实际写入时设置
            // 这里设置一个初始值，但实际写入的数据可能包含 metadata，所以会更大
            vb2_set_plane_payload(buffer, i, plane_size);
    }

    if (vbuf->field == V4L2_FIELD_ANY)
        vbuf->field = V4L2_FIELD_NONE;

    return 0;
}

void akvcam_buffers_buffer_queue(struct vb2_buffer *buffer)
{
    akvcam_buffers_t self = vb2_get_drv_priv(buffer->vb2_queue);
    struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(buffer);
    akvcam_buffers_buffer_t buf = container_of(vbuf, akvcam_buffers_buffer, vb);
    u64 timestamp_ns = 0;
    bool has_metadata = false;

    akpr_function();

    // 初始化 metadata_timestamp_ns 为 0（表示未设置）
    buf->metadata_timestamp_ns = 0;

    // 对于 OUTPUT device，检查数据是否包含 metadata（最后16字节）
    if (self->type == V4L2_BUF_TYPE_VIDEO_OUTPUT ||
        self->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
        // 对于 WRITE 模式，vb2_fop_write 会将实际写入的字节数设置到 payload
        // 但是，vb2_get_plane_payload 可能返回 buffer_prepare 中设置的值，而不是实际写入的值
        // 我们需要检查 buffer->planes[0].bytesused 是否包含实际写入的字节数
        size_t bytesused = vb2_get_plane_payload(buffer, 0);
        size_t plane_size = vb2_plane_size(buffer, 0);
        
        // 检查 buffer->planes[0].bytesused 是否包含实际写入的字节数
        // 对于 WRITE 模式，vb2_fop_write 会将实际写入的字节数设置到 planes[0].bytesused
        // 注意：buffer->planes 是一个数组，不能检查是否为 NULL
        if (buffer->planes[0].bytesused > 0) {
            bytesused = buffer->planes[0].bytesused;
            pr_info("AKVCAM: Using planes[0].bytesused=%zu (payload was %zu, plane_size=%zu)\n",
                   bytesused, vb2_get_plane_payload(buffer, 0), plane_size);
        } else {
            pr_info("AKVCAM: buffer_queue - payload=%zu, plane_size=%zu, planes[0].bytesused=%u\n",
                   bytesused, plane_size, buffer->planes[0].bytesused);
        }
        
        // 对于未压缩格式，如果 FFmpeg 写入了 plane_size + 16（包含 metadata），
        // bytesused 应该是 plane_size + 16
        // 如果 bytesused == plane_size，metadata 在 plane_size 位置（即 plane_size 到 plane_size + 16）
        
        if (bytesused == 0) {
            pr_info("AKVCAM: payload is 0, skipping metadata check\n");
        } else if (bytesused >= META_SIZE) {
            // 读取最后 16 字节的 metadata
            char meta_buf[META_SIZE];
            void *plane_vaddr = vb2_plane_vaddr(buffer, 0);

            if (plane_vaddr) {
                // 从数据末尾读取 metadata
                // 如果 bytesused > plane_size，说明包含 metadata，从 bytesused - 16 位置读取
                // 如果 bytesused == plane_size，对于未压缩格式，metadata 在 plane_size 位置
                size_t metadata_offset;
                
                if (bytesused > plane_size) {
                    // bytesused > plane_size，说明包含 metadata，从 bytesused - 16 位置读取
                    metadata_offset = bytesused - META_SIZE;
                } else if (bytesused == plane_size) {
                    // bytesused == plane_size，对于未压缩格式，metadata 在 plane_size 位置
                    // 假设 buffer 大小 >= plane_size + 16，从 plane_size 位置读取
                    metadata_offset = plane_size;
                } else {
                    // bytesused < plane_size，说明是压缩格式，从 bytesused - 16 位置读取
                    metadata_offset = bytesused - META_SIZE;
                }
                
                // 检查 metadata_offset 是否有效（不能超出 buffer 大小）
                if (metadata_offset + META_SIZE <= vb2_plane_size(buffer, 0)) {
                    memcpy(meta_buf, (char *)plane_vaddr + metadata_offset, META_SIZE);

                    // 调试：打印原始字节和读取位置
                    pr_info("AKVCAM: Parsed metadata - raw bytes: "
                           "%02x %02x %02x %02x %02x %02x %02x %02x | "
                           "%02x %02x %02x %02x %02x %02x %02x %02x, "
                           "bytesused=%zu, plane_size=%zu, metadata_offset=%zu\n",
                           meta_buf[0], meta_buf[1], meta_buf[2], meta_buf[3],
                           meta_buf[4], meta_buf[5], meta_buf[6], meta_buf[7],
                           meta_buf[8], meta_buf[9], meta_buf[10], meta_buf[11],
                           meta_buf[12], meta_buf[13], meta_buf[14], meta_buf[15],
                           bytesused, plane_size, metadata_offset);

                    // 解析大端序的 sec 和 usec（手动字节序转换）
                    u64 user_sec = ((u64)meta_buf[0] << 56) | ((u64)meta_buf[1] << 48) |
                                   ((u64)meta_buf[2] << 40) | ((u64)meta_buf[3] << 32) |
                                   ((u64)meta_buf[4] << 24) | ((u64)meta_buf[5] << 16) |
                                   ((u64)meta_buf[6] << 8)  | ((u64)meta_buf[7]);
                    u64 user_usec = ((u64)meta_buf[8] << 56) | ((u64)meta_buf[9] << 48) |
                                    ((u64)meta_buf[10] << 40) | ((u64)meta_buf[11] << 32) |
                                    ((u64)meta_buf[12] << 24) | ((u64)meta_buf[13] << 16) |
                                    ((u64)meta_buf[14] << 8)  | ((u64)meta_buf[15]);

                    pr_info("AKVCAM: Parsed - user_sec=%llu, user_usec=%llu\n",
                           user_sec, user_usec);

                    // 转换为纳秒时间戳
                    timestamp_ns = user_sec * 1000000000ULL + user_usec * 1000ULL;
                    buf->metadata_timestamp_ns = timestamp_ns;
                    has_metadata = true;

                    // 记录解析时间戳的日志
                    u64 timestamp_us = user_sec * 1000000ULL + user_usec;
                    u64 now_ns = ktime_get_ns();
                    u64 now_us = now_ns / 1000;
                    log_point("AKVCAM parse timestamp", timestamp_us, now_us);

                    // 调整 bytesused，移除 metadata 部分
                    if (bytesused > META_SIZE) {
                        vb2_set_plane_payload(buffer, 0, bytesused - META_SIZE);
                    }
                } else {
                    pr_info("AKVCAM: metadata_offset + META_SIZE exceeds buffer size\n");
                }
            } else {
                pr_info("AKVCAM: plane_vaddr is NULL, cannot read metadata\n");
            }
        } else {
            pr_info("AKVCAM: No metadata found - bytesused=%zu, plane_size=%zu, META_SIZE=%d\n",
                   bytesused, plane_size, META_SIZE);
        }
    }

    if (!mutex_lock_interruptible(&self->frames_mutex)) {
        list_add_tail(&buf->list, &self->buffers);
        mutex_unlock(&self->frames_mutex);
    }
}

int akvcam_buffers_start_streaming(struct vb2_queue *queue, unsigned int count)
{
    akvcam_buffers_t self = vb2_get_drv_priv(queue);
    UNUSED(count);

    akpr_function();
    self->sequence = 0;

    return akvcam_call_no_args(self, streaming_started);
}

void akvcam_buffers_stop_streaming(struct vb2_queue *queue)
{
    akvcam_buffers_t self = vb2_get_drv_priv(queue);

    akpr_function();
    akvcam_emit_no_args(self, streaming_stopped);

    if (!mutex_lock_interruptible(&self->frames_mutex)) {
        akvcam_buffers_buffer_t buf;
        akvcam_buffers_buffer_t node;

        list_for_each_entry_safe(buf, node, &self->buffers, list) {
            vb2_buffer_done(&buf->vb.vb2_buf, VB2_BUF_STATE_ERROR);
            list_del(&buf->list);
        }

        mutex_unlock(&self->frames_mutex);
    }
}

void akvcam_buffers_set_last_frame_timestamp(akvcam_buffers_t self, u64 timestamp_ns)
{
    if (self)
        self->last_frame_timestamp_ns = timestamp_ns;
}

u64 akvcam_buffers_get_last_frame_timestamp(akvcam_buffers_t self)
{
    return self ? self->last_frame_timestamp_ns : 0;
}

static const struct vb2_ops akvcam_akvcam_buffers_queue_ops = {
    .queue_setup     = akvcam_buffers_queue_setup,
    .buf_prepare     = akvcam_buffers_buffer_prepare,
    .buf_queue       = akvcam_buffers_buffer_queue,
    .start_streaming = akvcam_buffers_start_streaming,
    .stop_streaming  = akvcam_buffers_stop_streaming,
    .wait_prepare    = vb2_ops_wait_prepare,
    .wait_finish     = vb2_ops_wait_finish,
};
