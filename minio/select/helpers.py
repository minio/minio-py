# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2019 MinIO, Inc.
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
minio.select.helpers
~~~~~~~~~~~~~~~

This module implements the helper functions for SelectObject responses.

:copyright: (c) 2019 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import codecs
from binascii import crc32

EVENT_RECORDS = 'Records'  # Event Type is Records
EVENT_PROGRESS = 'Progress'  # Event Type Progress
EVENT_STATS = 'Stats'  # Event Type Stats
EVENT_CONT = 'Cont'  # Event Type continue
EVENT_END = 'End'  # Event Type is End
EVENT_CONTENT_TYPE = "text/xml"  # Event content xml type
EVENT = 'event'  # Message Type is event
ERROR = 'error'  # Message Type is error


def calculate_crc(value):
    '''
    Returns the CRC using crc32
    '''
    return crc32(value) & 0xffffffff


def validate_crc(current_value, expected_value):
    '''
    Validate through CRC check
    '''
    return calculate_crc(current_value) == byte_int(expected_value)


def byte_int(data_bytes):
    '''
    Convert bytes to big-endian integer
    '''
    return int(codecs.encode(data_bytes, 'hex'), 16)
