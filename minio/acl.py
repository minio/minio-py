# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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

class Acl(object):
    @staticmethod
    def public_read_write():
        """ Public Read Write ACL """
        return 'public-read-write'

    @staticmethod
    def public_read():
        """ Public Read ACL"""
        return 'public-read'

    @staticmethod
    def authenticated_read():
        """ Authenticated Users Read """
        return 'authenticated-read'

    @staticmethod
    def private():
        """ Owner Read Write ACL"""
        return 'private'


def is_valid_acl(acl):
    if acl == Acl.public_read_write() or acl == Acl.public_read() \
            or acl == Acl.authenticated_read() or acl == Acl.private():
        return
    raise ValueError()
