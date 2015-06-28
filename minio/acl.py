# Minimal Object Storage Library, (C) 2015 Minio, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
__author__ = 'minio'


class Acl(object):
    @staticmethod
    def public_read_write():
        return 'public-read-write'

    @staticmethod
    def public_read():
        return 'public-read'

    @staticmethod
    def authenticated_read():
        return 'authenticated-read'

    @staticmethod
    def private():
        return 'private'
