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

#ifndef AKVCAM_DEBUG_CONTROL_H
#define AKVCAM_DEBUG_CONTROL_H

#include <linux/ftrace.h>

#define PERF_TAG "[VB2]"

// 定义 log_point 宏，使用 trace_printk 输出到 ftrace
// 格式: [VB2] <event_name>,<key_ts>,<now_ts>
// key_ts: v4l2_buffer 时间戳（微秒）
// now_ts: 当前 monotonic 时间戳（微秒）
#define log_point(name, key_ts, now_ts) \
    trace_printk("%s %s,%llu,%llu\n", PERF_TAG, name, (unsigned long long)key_ts, (unsigned long long)now_ts)

#endif // AKVCAM_DEBUG_CONTROL_H

