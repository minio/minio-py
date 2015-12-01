# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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

from __future__ import absolute_import
import io

from .parsers import parse_error

class HTTPReadSeeker(io.IOBase):
    """
    HTTP Read Seeker implements seekable stream.

    This class is also compatible with the Python standard library's :mod:`io`
    module, and can hence be treated as a readable object in the context of that
    framework.

    :param api :class:`Minio <Minio>`
    :param bucket_name
    :param object_name
    """
    def __init__(self, api, bucket_name, object_name):
        self._api = api
        self._bucket_name = bucket_name
        self._object_name = object_name
        self._is_read = False
        self._stat = None
        self._offset = 0
        self._reader = None

    def seek(self, offset, whence):
        ## TODO: whence value of '1' and '2' are not implemented yet.
        self._offset = offset

    def seekable(self):
        # This method is required for `io` module compatibility.
        return True

    def readable(self):
        # This method is required for `io` module compatibility.
        return True

    def readinto(self, b):
        # This method is required for `io` module compatibility.
        temp = self.read(len(b))
        if len(temp) == 0:
            return 0
        else:
            b[:len(temp)] = temp
            return len(temp)

    def stream(self, amt=2**20):
        if self._is_read is False:
            response = self._api._get_partial_object(self._bucket_name,
                                                     self._object_name,
                                                     self._offset, 0)
            if response.status != 206 and response.status != 200:
                parse_error(response, self._bucket_name+'/'+self._object_name)

            self._reader = response
            self._is_read = True

        return self._reader.stream(amt=amt)

    def read(self, amt=None):
        data = None
        if self._is_read is False:
            response = self._api._get_partial_object(self._bucket_name,
                                                         self._object_name,
                                                         self._offset, 0)

            if response.status != 206 and response.status != 200:
                parse_error(response, self._bucket_name+'/'+self._object_name)

            self._reader = response
            self._is_read = True

        if amt is None:
            data = self._reader.read()
        else:
            data = self._reader.read(amt)

        return data

    def stat(self):
        self._stat = self._api.stat_object(self._bucket_name, self._object_name)
        return self._stat
