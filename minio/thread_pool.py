# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2017 MinIO, Inc.
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
minio.thread_pool
~~~~~~~~~~~~

This module implements a thread pool API to run several tasks
in parallel. Tasks results can also be retrieved.

:copyright: (c) 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from threading import BoundedSemaphore, Thread

from .compat import PYTHON2

if PYTHON2:
    from Queue import Queue  # pylint: disable=import-error
else:
    from queue import Queue


class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """

    def __init__(self, tasks_queue, results_queue, exceptions_queue):
        Thread.__init__(self)
        self.tasks_queue = tasks_queue
        self.results_queue = results_queue
        self.exceptions_queue = exceptions_queue
        self.daemon = True
        self.start()

    def run(self):
        """ Continously receive tasks and execute them """
        while True:
            task = self.tasks_queue.get()
            if not task:
                self.tasks_queue.task_done()
                break
            # No exception detected in any thread,
            # continue the execution.
            if self.exceptions_queue.empty():
                # Execute the task
                func, args, kargs, cleanup_func = task
                try:
                    result = func(*args, **kargs)
                    self.results_queue.put(result)
                except Exception as ex:  # pylint: disable=broad-except
                    self.exceptions_queue.put(ex)
                finally:
                    cleanup_func()
            # Mark this task as done, whether an exception happened or not
            self.tasks_queue.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """

    def __init__(self, num_threads):
        self.results_queue = Queue()
        self.exceptions_queue = Queue()
        self.tasks_queue = Queue()
        self.sem = BoundedSemaphore(num_threads)
        self.num_threads = num_threads

    def add_task(self, func, *args, **kargs):
        """
        Add a task to the queue. Calling this function can block
        until workers have a room for processing new tasks. Blocking
        the caller also prevents the latter from allocating a lot of
        memory while workers are still busy running their assigned tasks.
        """
        self.sem.acquire()
        cleanup_func = self.sem.release
        self.tasks_queue.put((func, args, kargs, cleanup_func))

    def start_parallel(self):
        """ Prepare threads to run tasks"""
        for _ in range(self.num_threads):
            Worker(self.tasks_queue, self.results_queue, self.exceptions_queue)

    def result(self):
        """ Stop threads and return the result of all called tasks """
        # Send None to all threads to cleanly stop them
        for _ in range(self.num_threads):
            self.tasks_queue.put(None)
        # Wait for completion of all the tasks in the queue
        self.tasks_queue.join()
        # Check if one of the thread raised an exception, if yes
        # raise it here in the function
        if not self.exceptions_queue.empty():
            raise self.exceptions_queue.get()
        return self.results_queue
