import time
import sys
from queue import Empty
from threading import Thread
from .compat import queue


class Progress(Thread):
    def __init__(self, total_size, file_name, interval=1):
        Thread.__init__(self)
        self.daemon = True
        self.total_size = total_size
        self.display_queue = queue()
        self.current_size = 0
        self.file_name = file_name
        self.prefix = self.file_name + ': ' if self.file_name else ''
        self.sp = StatusPrinter(sys.stdout)
        self.start_t = time.time()
        self.interval = interval

    def run(self):
        displayed_time = 0

        while True:
            try:
                # display every 1 secs
                task = self.display_queue.get(timeout=1)
            except Empty:
                elapsed_time = time.time() - self.start_t
                if elapsed_time > displayed_time:
                    displayed_time = elapsed_time
                self.sp.print_status(
                    self.prefix + format_meter(self.current_size, self.total_size, displayed_time))
                continue
            prefix, now, total = task
            displayed_time = time.time() - self.start_t
            self.sp.print_status(self.prefix + format_meter(now, total, displayed_time))
            self.display_queue.task_done()
            if now == total:
                break

    def update(self, size):

        if self.current_size == 0:
            self.start()
            self.display_queue.put((self.prefix, 0, self.total_size))

        self.current_size += size
        self.display_queue.put((self.prefix, self.current_size, self.total_size))
        if self.current_size == self.total_size:
            self.display_queue.join()


def format_interval(t):
    mins, s = divmod(int(t), 60)
    h, m = divmod(mins, 60)
    if h:
        return '%d:%02d:%02d' % (h, m, s)
    else:
        return '%02d:%02d' % (m, s)


def format_meter(n, total, elapsed):
    # n - number of finished iterations
    # total - total number of iterations, or None
    # elapsed - number of seconds passed since start
    if n > total:
        total = None

    elapsed_str = format_interval(elapsed)
    n_to_mb = n / 1024 / 1024
    rate = '%5.2f' % (n_to_mb / elapsed) if elapsed else '?'
    frac = float(n) / total

    n_bars = 10
    bar_length = int(frac * n_bars)
    bar = '#' * bar_length + '-' * (n_bars - bar_length)

    percentage = '%3d%%' % (frac * 100)

    left_str = format_interval(elapsed / n * (total - n)) if n else '?'

    humanized_total = '%0.2f' % (total / 1024 / 1024) + ' MB'
    humanized_n = '%0.2f' % n_to_mb + ' MB'
    return '|%s| %s/%s %s [elapsed: %s left: %s, %s MB/sec]' % (
        bar, humanized_n, humanized_total, percentage, elapsed_str, left_str, rate)


class StatusPrinter(object):
    def __init__(self, file):
        self.file = file
        self.last_printed_len = 0

    def print_status(self, s):
        self.file.write('\r' + s + ' ' * max(self.last_printed_len - len(s), 0))
        self.file.flush()
        self.last_printed_len = len(s)
