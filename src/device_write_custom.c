/* akvcam, virtual camera for Linux.
 * Custom write implementation to support timestamp passthrough from ffmpeg
 * 
 * This file implements a custom write() handler that extracts hardware
 * timestamps embedded by ffmpeg in the data stream and propagates them
 * to connected capture devices.
 */

#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <media/videobuf2-v4l2.h>

#include "device.h"
#include "buffers.h"
#include "format.h"
#include "frame.h"
#include "list.h"
#include "log.h"

#define AKVCAM_TIMESTAMP_META_SIZE 16  // 8 bytes sec + 8 bytes usec

/* Helper to get monotonic timestamp in nanoseconds */
static inline u64 akvcam_get_monotonic_ns(void)
{
    return ktime_get_ns();
}

/* Helper function to extract big-endian 64-bit value */
static inline u64 akvcam_be64_to_cpu(const u8 *data)
{
    return ((u64)data[0] << 56) | ((u64)data[1] << 48) |
           ((u64)data[2] << 40) | ((u64)data[3] << 32) |
           ((u64)data[4] << 24) | ((u64)data[5] << 16) |
           ((u64)data[6] << 8)  | ((u64)data[7]);
}

/* Custom write function for akvcam output devices
 * This function intercepts write() calls and extracts timestamp metadata
 * appended by ffmpeg (16 bytes: 8B sec + 8B usec in big-endian format).
 * The timestamp is then propagated to all connected capture devices.
 */
ssize_t akvcam_device_write_with_timestamp(struct file *file,
                                           const char __user *buf,
                                           size_t count,
                                           loff_t *ppos)
{
    akvcam_device_t device = video_drvdata(file);
    akvcam_buffers_t buffers;
    akvcam_format_t format;
    akvcam_devices_list_t connected_devices;
    size_t frame_size;
    bool has_timestamp = false;
    u64 timestamp_sec = 0, timestamp_usec = 0;
    u8 meta_buf[AKVCAM_TIMESTAMP_META_SIZE];
    ssize_t result;
    size_t original_count = count;

    akpr_function();

    if (!device) {
        akpr_err("Invalid device\n");
        return -ENODEV;
    }

    buffers = akvcam_device_buffers_nr(device);
    format = akvcam_buffers_format(buffers);
    frame_size = akvcam_format_size(format);
    akvcam_format_delete(format);

    /* Always trace write calls to see what's happening */
    trace_printk("[VB2][AKVCAM] OUTPUT_Write_Called count=%zu frame_size=%zu expected_with_meta=%zu\n",
                 count, frame_size, frame_size + AKVCAM_TIMESTAMP_META_SIZE);

    /* Check if data contains timestamp metadata */
    if (count == frame_size + AKVCAM_TIMESTAMP_META_SIZE) {
        u64 sys_timestamp_ns, monotonic_ns;
        
        has_timestamp = true;
        
        /* Extract timestamp metadata from end of buffer */
        if (copy_from_user(meta_buf, buf + frame_size, AKVCAM_TIMESTAMP_META_SIZE)) {
            akpr_err("Failed to read timestamp metadata\n");
            return -EFAULT;
        }

        /* Parse big-endian timestamp */
        timestamp_sec = akvcam_be64_to_cpu(meta_buf);
        timestamp_usec = akvcam_be64_to_cpu(meta_buf + 8);
        
        /* Convert to nanoseconds for trace */
        sys_timestamp_ns = timestamp_sec * 1000000000ULL + timestamp_usec * 1000ULL;
        monotonic_ns = akvcam_get_monotonic_ns();

        trace_printk("[VB2][AKVCAM] OUTPUT_Write_Received sys_timestamp=%llu monotonic_timestamp=%llu sec=%llu usec=%llu\n",
                     sys_timestamp_ns, monotonic_ns, timestamp_sec, timestamp_usec);

        akpr_info("OUTPUT device: Extracted timestamp from ffmpeg: sec=%llu, usec=%llu\n",
                  timestamp_sec, timestamp_usec);

        /* Adjust count to exclude metadata for actual write */
        count = frame_size;
    } else if (count != frame_size) {
        u64 monotonic_ns = akvcam_get_monotonic_ns();
        trace_printk("[VB2][AKVCAM] OUTPUT_Write_NO_METADATA count=%zu frame_size=%zu monotonic_timestamp=%llu\n",
                     count, frame_size, monotonic_ns);
        akpr_warning("Unexpected write size: %zu (expected %zu or %zu)\n",
                     count, frame_size, frame_size + AKVCAM_TIMESTAMP_META_SIZE);
    } else {
        /* Exact frame size, no metadata */
        u64 monotonic_ns = akvcam_get_monotonic_ns();
        trace_printk("[VB2][AKVCAM] OUTPUT_Write_EXACT_SIZE count=%zu monotonic_timestamp=%llu\n",
                     count, monotonic_ns);
    }

    /* Propagate timestamp to all connected capture devices */
    if (has_timestamp) {
        u64 sys_timestamp_ns = timestamp_sec * 1000000000ULL + timestamp_usec * 1000ULL;
        u64 monotonic_ns = akvcam_get_monotonic_ns();
        
        connected_devices = akvcam_device_connected_devices_nr(device);
        akvcam_list_element_t it = NULL;
        
        int capture_count = 0;
        for (;;) {
            akvcam_device_t capture_device = akvcam_list_next(connected_devices, &it);
            if (!it)
                break;
            
            akvcam_buffers_t capture_buffers = akvcam_device_buffers_nr(capture_device);
            akvcam_buffers_set_pending_timestamp(capture_buffers, timestamp_sec, timestamp_usec);
            
            trace_printk("[VB2][AKVCAM] OUTPUT_Set_Pending_To_Capture sys_timestamp=%llu monotonic_timestamp=%llu capture_dev=%d capture_count=%d\n",
                         sys_timestamp_ns, monotonic_ns, akvcam_device_num(capture_device), capture_count);
            
            akpr_debug("Set timestamp for capture device /dev/video%d\n",
                      akvcam_device_num(capture_device));
            capture_count++;
        }
        
        if (capture_count == 0) {
            trace_printk("[VB2][AKVCAM] OUTPUT_Write_NO_CAPTURE_DEVICES sys_timestamp=%llu\n",
                         sys_timestamp_ns);
        }
    } else {
        trace_printk("[VB2][AKVCAM] OUTPUT_Write_NO_TIMESTAMP_TO_SET\n");
    }

    /* Call standard vb2 write handler */
    result = vb2_fop_write(file, buf, count, ppos);

    /* NOTE: Do NOT clear pending timestamp here!
     * The timestamp will be used later when akvcam_device_clock_run_once
     * transfers the frame from output to capture device.
     * The timestamp will be cleared in akvcam_buffers_write_frame after use.
     */

    /* Return original count including metadata if it was present */
    if (result > 0 && has_timestamp) {
        result = original_count;
    }

    return result;
}
