import time
import sys


class Progress(object):
    def __init__(self, total_size, desc):
        self.total_size = total_size
        self.current_size = 0
        self.desc = desc
        self.prefix = self.desc + ': ' if self.desc else ''
        self.sp = StatusPrinter(sys.stdout)

        self.start_t = time.time()

    def update(self, size):

        if self.current_size == 0:
            self.sp.print_status(self.prefix + format_meter(0, self.total_size, 0))

        cur_t = time.time()
        self.current_size += size
        self.sp.print_status(self.prefix + format_meter(size, self.total_size, cur_t - self.start_t))
        if self.current_size == self.total_size:
            self.done()

    def done(self):
        cur_t = time.time()
        self.sp.print_status(self.prefix + format_meter(self.total_size, self.total_size, cur_t - self.start_t))


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
    rate = '%5.2f' % (n / elapsed) if elapsed else '?'

    if total:
        frac = float(n) / total

        N_BARS = 10
        bar_length = int(frac * N_BARS)
        bar = '#' * bar_length + '-' * (N_BARS - bar_length)

        percentage = '%3d%%' % (frac * 100)

        left_str = format_interval(elapsed / n * (total - n)) if n else '?'

        return '|%s| %d/%d %s [elapsed: %s left: %s, %s iters/sec]' % (
            bar, n, total, percentage, elapsed_str, left_str, rate)

    else:
        return '%d [elapsed: %s, %s iters/sec]' % (n, elapsed_str, rate)


class StatusPrinter(object):
    def __init__(self, file):
        self.file = file
        self.last_printed_len = 0

    def print_status(self, s):
        self.file.write('\r' + s + ' ' * max(self.last_printed_len - len(s), 0))
        self.file.flush()
        self.last_printed_len = len(s)
