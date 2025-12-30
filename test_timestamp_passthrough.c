/* Test program for akvcam timestamp passthrough functionality
 * 
 * This program reads frames from an akvcam capture device and displays
 * the timestamps to verify that hardware timestamps are being passed through
 * correctly from ffmpeg.
 *
 * Compile:
 *   gcc -o test_timestamp test_timestamp_passthrough.c
 *
 * Usage:
 *   ./test_timestamp /dev/video1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <linux/videodev2.h>

#define BUFFER_COUNT 4

struct buffer {
    void *start;
    size_t length;
};

static void print_timestamp_info(struct v4l2_buffer *buf, int frame_num)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    
    uint64_t buf_ts_us = buf->timestamp.tv_sec * 1000000ULL + buf->timestamp.tv_usec;
    uint64_t now_us = now.tv_sec * 1000000ULL + now.tv_usec;
    int64_t diff_us = now_us - buf_ts_us;
    
    printf("Frame %4d: ", frame_num);
    printf("timestamp = %10ld.%06ld, ", buf->timestamp.tv_sec, buf->timestamp.tv_usec);
    printf("sequence = %6u, ", buf->sequence);
    printf("delay = %7.3f ms", diff_us / 1000.0);
    
    if (buf->flags & V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC) {
        printf(" [MONOTONIC]");
    }
    if (buf->flags & V4L2_BUF_FLAG_TIMESTAMP_COPY) {
        printf(" [COPY]");
    }
    
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <video_device>\n", argv[0]);
        fprintf(stderr, "Example: %s /dev/video1\n", argv[0]);
        return 1;
    }
    
    const char *dev_name = argv[1];
    int fd;
    struct v4l2_capability cap;
    struct v4l2_format fmt;
    struct v4l2_requestbuffers req;
    struct buffer buffers[BUFFER_COUNT];
    enum v4l2_buf_type type;
    int i;
    
    printf("Opening device: %s\n", dev_name);
    
    /* Open device */
    fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    
    /* Query capabilities */
    if (ioctl(fd, VIDIOC_QUERYCAP, &cap) < 0) {
        perror("VIDIOC_QUERYCAP");
        close(fd);
        return 1;
    }
    
    printf("Driver: %s\n", cap.driver);
    printf("Card: %s\n", cap.card);
    printf("Bus info: %s\n", cap.bus_info);
    
    if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
        fprintf(stderr, "Device does not support video capture\n");
        close(fd);
        return 1;
    }
    
    if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
        fprintf(stderr, "Device does not support streaming I/O\n");
        close(fd);
        return 1;
    }
    
    /* Get current format */
    memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_G_FMT, &fmt) < 0) {
        perror("VIDIOC_G_FMT");
        close(fd);
        return 1;
    }
    
    printf("Format: %dx%d, fourcc: %c%c%c%c\n",
           fmt.fmt.pix.width, fmt.fmt.pix.height,
           fmt.fmt.pix.pixelformat & 0xFF,
           (fmt.fmt.pix.pixelformat >> 8) & 0xFF,
           (fmt.fmt.pix.pixelformat >> 16) & 0xFF,
           (fmt.fmt.pix.pixelformat >> 24) & 0xFF);
    
    /* Request buffers */
    memset(&req, 0, sizeof(req));
    req.count = BUFFER_COUNT;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    
    if (ioctl(fd, VIDIOC_REQBUFS, &req) < 0) {
        perror("VIDIOC_REQBUFS");
        close(fd);
        return 1;
    }
    
    if (req.count < 2) {
        fprintf(stderr, "Insufficient buffer memory\n");
        close(fd);
        return 1;
    }
    
    printf("Allocated %d buffers\n", req.count);
    
    /* Map buffers */
    for (i = 0; i < req.count; i++) {
        struct v4l2_buffer buf;
        
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;
        
        if (ioctl(fd, VIDIOC_QUERYBUF, &buf) < 0) {
            perror("VIDIOC_QUERYBUF");
            close(fd);
            return 1;
        }
        
        buffers[i].length = buf.length;
        buffers[i].start = mmap(NULL, buf.length,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED,
                               fd, buf.m.offset);
        
        if (buffers[i].start == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return 1;
        }
    }
    
    /* Queue all buffers */
    for (i = 0; i < req.count; i++) {
        struct v4l2_buffer buf;
        
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = i;
        
        if (ioctl(fd, VIDIOC_QBUF, &buf) < 0) {
            perror("VIDIOC_QBUF");
            close(fd);
            return 1;
        }
    }
    
    /* Start streaming */
    type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMON, &type) < 0) {
        perror("VIDIOC_STREAMON");
        close(fd);
        return 1;
    }
    
    printf("\nStarting capture (press Ctrl+C to stop)...\n");
    printf("%-10s %-20s %-10s %-15s %s\n", 
           "Frame", "Timestamp", "Sequence", "Delay (ms)", "Flags");
    printf("-------------------------------------------------------------------\n");
    
    /* Capture loop */
    int frame_count = 0;
    uint64_t last_ts = 0;
    
    while (1) {
        struct v4l2_buffer buf;
        
        memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        
        /* Dequeue buffer */
        if (ioctl(fd, VIDIOC_DQBUF, &buf) < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            perror("VIDIOC_DQBUF");
            break;
        }
        
        /* Print timestamp info */
        print_timestamp_info(&buf, frame_count);
        
        /* Check for timestamp monotonicity */
        uint64_t current_ts = buf.timestamp.tv_sec * 1000000ULL + buf.timestamp.tv_usec;
        if (frame_count > 0 && current_ts <= last_ts) {
            printf("  WARNING: Timestamp not monotonic! (current: %llu, last: %llu)\n",
                   current_ts, last_ts);
        }
        last_ts = current_ts;
        
        /* Requeue buffer */
        if (ioctl(fd, VIDIOC_QBUF, &buf) < 0) {
            perror("VIDIOC_QBUF");
            break;
        }
        
        frame_count++;
        
        /* Stop after 100 frames for testing */
        if (frame_count >= 100) {
            printf("\nCaptured 100 frames, stopping...\n");
            break;
        }
    }
    
    /* Stop streaming */
    type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd, VIDIOC_STREAMOFF, &type) < 0) {
        perror("VIDIOC_STREAMOFF");
    }
    
    /* Unmap buffers */
    for (i = 0; i < req.count; i++) {
        munmap(buffers[i].start, buffers[i].length);
    }
    
    close(fd);
    
    printf("\nTest completed successfully!\n");
    printf("Total frames captured: %d\n", frame_count);
    
    return 0;
}
