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

"""
minio.io
~~~~~~~~~~~~~~~

This module contains HTTPReadSeeker implementation which powers
resumable downloads.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import
import io

from .error import ResponseError


class HTTPReadSeeker(io.IOBase):
    """
    HTTP Read Seeker implements seekable stream.

    This class is also compatible with the Python standard library's :mod:`io`
    module, and can hence be treated as a readable object in the context of
    that framework.

    :param api :class:`Minio <Minio>`
    :param bucket_name: Bucket name of which the object is part of.
    :param object_name: Object name for which :class:`HTTPReadSeeker`
       is created.
    """
    def __init__(self, api, bucket_name, object_name):
        self._api = api
        self._bucket_name = bucket_name
        self._object_name = object_name
        self._is_read = False
        self._stat = None
        self._offset = 0
        self._total_read = 0
        self._reader = None

    def seek(self, offset, whence=0):
        """
        Change the stream position to the given byte *offset*.  *offset* is
        interpreted relative to the position indicated by *whence*. The default
        value for *whence* is :data:`SEEK_SET`.  Values for *whence* are:

        * :data:`SEEK_SET` or ``0`` -- start of the stream (the default);
        *offset* should be zero or positive

        NOT SUPPORTED YET
        ~~~~~~~~~~~~~
        * :data:`SEEK_CUR` or ``1`` -- current stream position; *offset* may
        be negative
        * :data:`SEEK_END` or ``2`` -- end of the stream; *offset* is usually
        negative

        :return: Return the new absolute position.
        """
        # TODO: whence value of '1' and '2' are not implemented yet.
        if offset < 0 and whence == 0:
            raise ValueError('Invalid offset size cannot be negative '
                             'for SEEK_SET')
        self._offset = offset
        return self._offset

    def seekable(self):
        """
        Return ``True`` if the stream supports random access.
        :return: True always.
        """
        # This method is required for `io` module compatibility.
        return True

    def readable(self):
        """
        Return ``True`` if the stream supports read access.
        :return: True always.
        """
        # This method is required for `io` module compatibility.
        return True

    def readinto(self, buf):
        """
        Read up to len(buf) bytes into bytearray *buf* and return the number
        of bytes read.

        Like :meth:`read`, multiple reads may be issued to the underlying
        raw stream, unless the latter is 'interactive'.

        :param buf: Bytearray to read into.
        :return: Length of the read bytes.
        """
        # This method is required for `io` module compatibility.
        temp = self.read(len(buf))
        temp_length = len(temp)
        if temp_length == 0:
            return 0
        buf[:temp_length] = temp
        self._total_read += temp_length
        return temp_length

    def stream(self, amt=2**20):
        """
        A generator wrapper for the read() method. A call will block until
        ``amt`` bytes have been read from the connection or until the
        connection is closed.
            Raise :exc:`ResponseError` on failure.
        :param amt:
            How much of the content to read. The generator will return up to
            much data per iteration, but may return less.
        """
        if self._is_read is False:
            response = self._api.get_partial_object(self._bucket_name,
                                                    self._object_name,
                                                    self._offset, 0)
            if response.status != 206 and response.status != 200:
                response_error = ResponseError(response)
                raise response_error.get(self._bucket_name, self._object_name)

            self._reader = response
            self._is_read = True

        self._total_read += amt
        return self._reader.stream(amt=amt)

    def read(self, amt=None):
        """
        Similar to :meth:`urllib3.HTTPResponse.read`, but with amt option.
            Raise :exc:`ResponseError` on failure.
        :param amt:
            How much of the content to read.
        """
        data = None
        if self._is_read is False:
            # If reading is not started yet, get a new response reader
            # for a specified offset.
            response = self._api.get_partial_object(self._bucket_name,
                                                    self._object_name,
                                                    self._offset, 0)

            if response.status != 206 and response.status != 200:
                response_error = ResponseError(response)
                raise response_error.get(self._bucket_name, self._object_name)

            self._reader = response
            self._is_read = True

        if amt is None:
            data = self._reader.read()
        else:
            data = self._reader.read(amt)

        self._total_read = len(data)
        return data

    def getsize(self):
        """
        Return the size of the Seekable stream.  Raise :exc:`ResponseError`
        if the file does not exist or is inaccessible.
        """
        self._stat = self._api.stat_object(self._bucket_name,
                                           self._object_name)
        return self._stat.size
