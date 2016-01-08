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
minio.part

This module implements a part Object which gates readers.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import
import io


class SectionFile(io.FileIO):
    """
    SectionFile is an object wrapper over FileIO.

    returns a class:`SectionFile` that reads from
       *reader* and stops with EOF after *limit* bytes.

    :param reader: Input class:`io.FileIO`
    :param limit: Trigger EOF after limit bytes.
    """
    def __init__(self, reader, limit):
        self.reader = reader
        self._limit = limit
        self._offset_location = 0

    def read(self, amt=4*1024):
        """
        Similar to :meth:`io.read`, with amt option.

        :param amt:
            How much of the content to read.
        """
        data = self.reader.read(amt)
        # If we really reach EOF return here.
        if not data and len(data) == 0:
            return b''
        self._offset_location += len(data)
        # If offset is bigger than size. Treat it as EOF return here.
        if self._offset_location > self._limit:
            # seek back frivolous read if any.
            self.reader.seek(-len(data), 1)
            # return empty bytes to indicate EOF.
            return b''
        return data

    def seek(self, offset, whence=0):
        """
        Reposition read file offset.

        :param offset: offset value to set to.
        :param whence: Supports 0, 1 or 2 values.
           0 - offset is set to *offset*.
           1 - offset is set to current location plus *offset*.
           2 - offset is set to size of the file plus *offset*.
        """
        # Handle whence for internal offsets.
        if whence == 0:
            if offset < 0:
                raise IOError('invalid argument offset cannot be '
                              'negative for whence "0"')
            self._offset_location = offset
        elif whence == 1:
            if self._offset_location + offset > self._limit:
                raise ValueError('offset reaches beyond limit')
            self._offset_location += offset
        elif whence == 2:
            if offset > 0:
                raise ValueError('offset cannot be positive for whence "2"')
            if self._limit + offset < 0:
                raise ValueError('effective offset leads to negative location')
            self._offset_location = self._limit + offset
        else:
            raise ValueError('invalid whence: ', whence)
        # Pass down the value to wrapped FileIO.
        return self.reader.seek(offset, whence)
