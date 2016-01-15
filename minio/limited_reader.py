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

This module implements a Limited Reader.

A LimitedReader reads from *reader* but limits the amount
of data returned to just *limit* bytes. Each call to Read
updates *limit* to reflect the new amount remaining.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import
import io


class LimitedReader(io.BufferedIOBase):
    """
    LimitedReader returns a Reader that reads from *reader*
    but stops with EOF after *limit* bytes.
    
    LimitedReader is a wrapper over BufferedIOBase.

    returns a class:`LimitedReader` that reads from
       *reader* and stops with EOF after *limit* bytes.

    :param reader: Input class:`io.BufferedIOBase`
    :param limit: Trigger EOF after limit bytes.
    """
    def __init__(self, reader, limit):
        self.reader = reader
        self._limit = limit
        self._offset_location = 0

    def read(self, amt=64*1024):
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
