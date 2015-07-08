# Minimal Object Storage Library, (C) 2015 Minio, Inc.
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
__author__ = 'minio'


class LazyIterator(object):
    def __init__(self, generator):
        self.generator = generator
        self.values = []

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        if self.generator is None:
            # should never see this, but we'll be defensive
            raise StopIteration()
        if len(self.values) == 0:
            self.values, self.generator = self.generator()
        if len(self.values) > 0:
            return self.values.pop(0)
        raise StopIteration()
