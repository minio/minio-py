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
minio.select.reader
~~~~~~~~~~~~~~~

This module implements the reader for SelectObject response body.

:copyright: (c) 2019 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import

import io
import sys

from binascii import crc32
from xml.etree import cElementTree
from xml.etree.cElementTree import ParseError

from .helpers import (EVENT_RECORDS, EVENT_PROGRESS,
                      EVENT_STATS, EVENT_CONT,
                      EVENT, EVENT_CONTENT_TYPE,
                      EVENT_END, ERROR)

from .helpers import (validate_crc, calculate_crc, byte_int)
from .errors import (SelectMessageError, SelectCRCValidationError)

def _extract_header(header_bytes):
    """
    populates the header map after reading the header in bytes
    """
    header_map = {}
    header_byte_parsed = 0
    # While loop ends when all the headers present are read
    # header contains multipe headers
    while header_byte_parsed < len(header_bytes):
        header_name_byte_length = byte_int(header_bytes[header_byte_parsed:header_byte_parsed+1])
        header_byte_parsed += 1
        header_name = \
            header_bytes[header_byte_parsed:
                         header_byte_parsed+header_name_byte_length]
        header_byte_parsed += header_name_byte_length
        # Header Value Type is of 1 bytes and is skipped
        header_byte_parsed += 1
        value_string_byte_length = \
            byte_int(header_bytes[header_byte_parsed:
                                  header_byte_parsed+2])
        header_byte_parsed += 2
        header_value = \
            header_bytes[header_byte_parsed:
                         header_byte_parsed+value_string_byte_length]
        header_byte_parsed += value_string_byte_length
        header_map[header_name.decode("utf-8").lstrip(":")] = \
            header_value.decode("utf-8").lstrip(":")
    return header_map

def _parse_stats(stats):
    """
    Parses stats XML and populates the stat dict.
    """
    stat = {}
    for attribute in cElementTree.fromstring(stats):
        if attribute.tag == 'BytesScanned':
            stat['BytesScanned'] = attribute.text
        elif attribute.tag == 'BytesProcessed':
            stat['BytesProcessed'] = attribute.text
        elif attribute.tag == 'BytesReturned':
            stat['BytesReturned'] = attribute.text

    return stat

class SelectObjectReader(object):
    """
    SelectObjectReader returns a Reader that upon read
    returns queried data, but stops when the response ends.
    LimitedRandomReader is compatible with BufferedIOBase.
    """
    def __init__(self, response):
        self.response = response
        self.remaining_bytes = bytes()
        self.stat = {}
        self.prog = {}

    def readable(self):
        return True

    def writeable(self):
        return False

    def close(self):
        self.response.close()

    def stats(self):
        return self.stat

    def progress(self):
        return self.prog

    def __extract_message(self):
        """
        Process the response sent from server.
        https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectSELECTContent.html
        """

        crc_bytes = io.BytesIO()
        total_bytes_len = self.response.read(4)
        if len(total_bytes_len) == 0:
            return {}

        total_length = byte_int(total_bytes_len)
        header_bytes_len = self.response.read(4)
        if len(header_bytes_len) == 0:
            return {}

        header_len = byte_int(header_bytes_len)

        crc_bytes.write(total_bytes_len)
        crc_bytes.write(header_bytes_len)

        prelude_bytes_crc = self.response.read(4)
        if not validate_crc(crc_bytes.getvalue(), prelude_bytes_crc):
            raise SelectCRCValidationError(
                {"Checksum Mismatch, PreludeCRC of " +
                 str(calculate_crc(crc_bytes.getvalue())) +
                 " does not equal expected CRC of " +
                 str(byte_int(prelude_bytes_crc))})

        crc_bytes.write(prelude_bytes_crc)

        header_bytes = self.response.read(header_len)
        if len(header_bytes) == 0:
            raise SelectMessageError(
                "Premature truncation of select message header"+
                ", server is sending corrupt message?")

        crc_bytes.write(header_bytes)

        header_map = _extract_header(header_bytes)
        payload_length = total_length - header_len - int(16)
        payload_bytes = b''
        event_type = header_map["event-type"]
        if header_map["message-type"] == ERROR:
            raise SelectMessageError(
                header_map["error-code"] + ":\"" + \
                header_map["error-message"] + "\"")
        elif header_map["message-type"] == EVENT:
            if event_type == EVENT_END:
                pass
            elif event_type == EVENT_CONT:
                pass
            elif event_type == EVENT_STATS:
                content_type = header_map["content-type"]
                if content_type != EVENT_CONTENT_TYPE:
                    raise SelectMessageError(
                        "Unrecognized content-type {0}".format(content_type))
                else:
                    payload_bytes = self.response.read(payload_length)
                    self.stat = _parse_stats(payload_bytes)

            elif event_type == EVENT_RECORDS:
                payload_bytes = self.response.read(payload_length)
        else:
            raise SelectMessageError(
                "Unrecognized message-type {0}".format(header_map["message-type"])
            )

        crc_bytes.write(payload_bytes)

        message_crc = self.response.read(4)
        if len(message_crc) == 0:
            return {}

        if not validate_crc(crc_bytes.getvalue(),
                            message_crc):
            raise SelectCRCValidationError(
                {"Checksum Mismatch, MessageCRC of " +
                 str(calculate_crc(crc_bytes.getvalue())) +
                 " does not equal expected CRC of " +
                 str(byte_int(message_crc))})

        message = {event_type: payload_bytes}
        return message

    def stream(self, num_bytes=32*1024):
        """
        extract each record from the response body ... and buffer it.
        send only up to requested bytes such as message[:num_bytes]
        rest is buffered and added to the next iteration.

        caller should call self.close() to close the stream.
        """
        while not self.response.isclosed():
            if len(self.remaining_bytes) == 0:
                message = self.__extract_message()
                if EVENT_RECORDS in message:
                    self.remaining_bytes = message.get(EVENT_RECORDS, b'')
                else:
                    # For all other events continue
                    continue

            result = self.remaining_bytes
            if num_bytes < len(self.remaining_bytes):
                result = self.remaining_bytes[:num_bytes]
            self.remaining_bytes = self.remaining_bytes[len(result):]

            if result == b'':
                break
            if sys.version_info.major == 3:
                yield result.decode('utf-8', errors='ignore')
            else:
                # Python 2.x needs explicit conversion.
                yield result.decode('utf-8', errors='ignore').encode('utf-8')
