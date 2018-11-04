# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2018 Minio, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
minio.progress

This module implements a progress printer while uploading object

:copyright: (c) 2018 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import time
import sys
from threading import Thread
from .compat import queue, queue_empty


_BAR_SIZE = 10
_KILOBYTE = 1024
_BAR = '#'
_REMAINING_BAR = '-'

_UNKNOWN_SIZE = '?'
_STR_MEGABYTE = ' MB'

_HOURS_OF_ELAPSED = '%d:%02d:%02d'
_MINUTES_OF_ELAPSED = '%02d:%02d'

_RATE_FORMAT = '%5.2f'
_PERCENTAGE_FORMAT = '%3d%%'
_HUMANINZED_FORMAT = '%0.2f'

_DISPLAY_FORMAT = '|%s| %s/%s %s [elapsed: %s left: %s, %s MB/sec]'

_REFRESH_CHAR = '\r'


class Progress(Thread):
    """
        Constructs a :class:`Progress` object.
        :param total_size: Total size of object.
        :param object_name: Object name to be showed.
        :param interval: The time interval at which progress will be displayed.

        :return: :class:`Progress` object
    """
    def __init__(self, total_size, object_name, interval=1):
        Thread.__init__(self)
        self.daemon = True
        self.total_size = total_size
        self.object_name = object_name
        self.interval = interval

        self.display_queue = queue()
        self.current_size = 0
        self.prefix = self.object_name + ': ' if self.object_name else ''
        self.sp = StatusPrinter(sys.stdout)
        self.start_t = time.time()

    def run(self):

        displayed_time = 0
        while True:
            try:
                # display every interval secs
                task = self.display_queue.get(timeout=self.interval)
            except queue_empty:
                elapsed_time = time.time() - self.start_t
                if elapsed_time > displayed_time:
                    displayed_time = elapsed_time
                self.sp.print_status(
                    self.prefix + format_meter(self.current_size,
                                               self.total_size, displayed_time))
                continue
            prefix, now, total = task
            displayed_time = time.time() - self.start_t
            self.sp.print_status(self.prefix + format_meter(now, total, displayed_time))
            self.display_queue.task_done()
            if now == total:
                break

    def update(self, size):
        """
        Update object size to be showed.
        :param size: Object size to be showed. The object size should be in bytes.
        """
        if not isinstance(size, int):
            raise ValueError('{} type can not be displayed. '
                             'Please change it to Int.'.format(type(size)))

        if self.current_size == 0:
            self.start()
            self.display_queue.put((self.prefix, 0, self.total_size))

        self.current_size += size
        self.display_queue.put((self.prefix, self.current_size, self.total_size))
        if self.current_size == self.total_size:
            self.display_queue.join()


def format_interval(seconds):
    """
    Consistent time format to be displayed on the elapsed time in screen.
    :param seconds: seconds
    """
    minutes, seconds = divmod(int(seconds), 60)
    hours, m = divmod(minutes, 60)
    if hours:
        return _HOURS_OF_ELAPSED % (hours, m, seconds)
    else:
        return _MINUTES_OF_ELAPSED % (m, seconds)


def format_meter(n, total, elapsed):
    """
    Consistent format to be displayed on the screen.
    :param n: Number of finished object size
    :param total: Total object size
    :param elapsed: number of seconds passed since start
    """

    n_to_mb = n / _KILOBYTE / _KILOBYTE
    elapsed_str = format_interval(elapsed)

    rate = _RATE_FORMAT % (n_to_mb / elapsed) if elapsed else _UNKNOWN_SIZE
    frac = float(n) / total
    bar_length = int(frac * _BAR_SIZE)
    bar = _BAR * bar_length + _REMAINING_BAR * (_BAR_SIZE - bar_length)
    percentage = _PERCENTAGE_FORMAT % (frac * 100)
    left_str = format_interval(elapsed / n * (total - n)) if n else _UNKNOWN_SIZE

    humanized_total = _HUMANINZED_FORMAT % (total / _KILOBYTE / _KILOBYTE) + _STR_MEGABYTE
    humanized_n = _HUMANINZED_FORMAT % n_to_mb + _STR_MEGABYTE

    return _DISPLAY_FORMAT % (
        bar, humanized_n, humanized_total, percentage, elapsed_str, left_str, rate)


class StatusPrinter(object):
    """
    Constructs a `StatusPrinter`
    :param stdout: standard output
    """
    def __init__(self, stdout):
        self.stdout = stdout
        self.last_printed_len = 0

    def print_status(self, s):
        self.stdout.write(_REFRESH_CHAR + s + ' ' * max(self.last_printed_len - len(s), 0))
        self.stdout.flush()
        self.last_printed_len = len(s)
