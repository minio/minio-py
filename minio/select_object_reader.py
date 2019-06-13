# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017, 2018, 2019 MinIO, Inc.
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


import io
import codecs

from binascii import crc32
from xml.etree import cElementTree
from .error import InvalidXMLError
from xml.etree.cElementTree import ParseError

from .helpers import (READ_SIZE_SELECT, EVENT_RECORDS,
                      EVENT_PROGRESS, EVENT_STATS, EVENT, EVENT_END, ERROR)


class CRCValidationError(Exception):
    '''
    Raised in case of CRC mismatch
    '''


def calculate_crc(value):
    '''
    Returns the CRC using crc32
    '''
    return crc32(value) & 0xffffffff


def validate_crc(current_value, expected_value):
    '''
    Validate through CRC check
    '''
    crc_current = calculate_crc(current_value)
    crc_expected = byte_int(expected_value)
    if crc_current == crc_expected:
        return True
    return False


def byte_int(data_bytes):
    '''
    Convert bytes to big-endian integer
    '''
    return int(codecs.encode(data_bytes, 'hex'), 16)


class SelectObjectReader(object):
    """
    SelectObjectReader returns a Reader that upon read
    returns queried data, but stops when the response ends.
    LimitedRandomReader is compatible with BufferedIOBase.
    """
    def __init__(self, response):
        self.response = response
        self.remaining_bytes = bytearray()
        self.stat = {}
        self.prog = {}

    def readable(self):
        return True

    def writeable(self):
        return False

    @property
    def closed(self):
        return self.response.isclosed()

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
        rec = bytearray()
        read_buffer = READ_SIZE_SELECT
        # Messages read in chunks of read_buffer bytes
        chunked_message = self.response.read(read_buffer)
        total_byte_parsed = 0
        if len(chunked_message) == 0:
            self.close()
            return b''

        #  The first 4 bytes gives the total_byte_length and then
        #  complete message is extracted
        while total_byte_parsed < read_buffer:
            # Case 1 - If the total_byte_length is partially read
            # in the chunked message , then complete the total_byte_length
            # by reading the required bytes from response and then
            # generate the complete message
            if read_buffer - total_byte_parsed <= 4:
                value = chunked_message[total_byte_parsed:
                                        total_byte_parsed +
                                        (read_buffer - total_byte_parsed) +
                                        1]
                rem_bytes = self.response.read(4 - (read_buffer -
                                                    total_byte_parsed))
                message = value + rem_bytes + \
                    self.response.read(byte_int(value+rem_bytes)-4)
                end_status = self.__decode_message(message, rec)
                total_byte_parsed = 0
                break
            else:
                total_byte_length = chunked_message[total_byte_parsed: total_byte_parsed + 4]
                # Case 2 - Incomplete message in chunked message ,
                # so creating the complete message by reading the
                # total_byte_length- len_read from the response message.
                if total_byte_parsed + byte_int(total_byte_length) > read_buffer:
                    len_read = len(chunked_message[total_byte_parsed:])
                    message = chunked_message[total_byte_parsed:] + \
                        self.response.read(byte_int(total_byte_length)-len_read)
                    end_status = self.__decode_message(message, rec)
                    total_byte_parsed += byte_int(total_byte_length)
                # Case 3- the complete message is present in chunked
                # messsage.
                else:
                    message = chunked_message[total_byte_parsed:
                                              total_byte_parsed +
                                              byte_int(total_byte_length)]
                    total_byte_parsed += byte_int(total_byte_length)
                    end_status = self.__decode_message(message, rec)
            if end_status:
                break
        return rec

    def __extract_header(self, header, header_length):
        """
        populates the header map after reading the header
        """
        header_map = {}
        header_byte_parsed = 0
        # While loop ends when all the headers present are read
        # header contains multipe headers
        while header_byte_parsed < header_length:
            header_name_byte_length = \
                byte_int(header[header_byte_parsed: header_byte_parsed+1])
            header_byte_parsed += 1
            header_name = \
                header[header_byte_parsed:
                       header_byte_parsed+header_name_byte_length]
            header_byte_parsed += header_name_byte_length
            # Header Value Type is of 1 bytes and is skipped
            header_byte_parsed += 1
            value_string_byte_length = \
                byte_int(header[header_byte_parsed:
                                header_byte_parsed+2])
            header_byte_parsed += 2
            header_value = \
                header[header_byte_parsed:
                       header_byte_parsed+value_string_byte_length]
            header_byte_parsed += value_string_byte_length
            header_map[header_name.decode("utf-8").lstrip(":")] = \
                header_value.decode("utf-8").lstrip(":")
        return header_map

    def __read_stats(self, stats):
        """
        pupulates the stat dict.
        """
        root = cElementTree.fromstring(stats)
        for attribute in root:
            if attribute.tag == 'BytesScanned':
                self.stat['BytesScanned'] = attribute.text
            elif attribute.tag == 'BytesProcessed':
                self.stat['BytesProcessed'] = attribute.text
            elif attribute.tag == 'BytesReturned':
                self.stat['BytesReturned'] = attribute.text

    def __parse_message(self, header_map, payload, payload_length, record):
        '''
        Parses the message
        '''
        if header_map["message-type"] == ERROR:
            error = header_map["error-code"] + ":\"" +\
                    header_map["error-message"] + "\""
        if header_map["message-type"] == EVENT:
            # Fetch the content-type
            content_type = header_map["content-type"]
            # Fetch the event-type
            event_type = header_map["event-type"]
            if event_type == EVENT_RECORDS:
                record += payload[0:payload_length]
            elif event_type == EVENT_PROGRESS:
                if content_type == "text/xml":
                    progress = payload[0:payload_length]
            elif event_type == EVENT_STATS:
                if content_type == "text/xml":
                    self.__read_stats(payload[0:payload_length])

    def __decode_message(self, message, rec):
        end_status = False
        total_byte_length = message[0:4]  # total_byte_length is of 4 bytes
        headers_byte_length = message[4: 8]  # headers_byte_length is 4 bytes
        prelude_crc = message[8:12]  # prelude_crc is of 4 bytes
        header = message[12:12+byte_int(headers_byte_length)]
        payload_length = byte_int(total_byte_length) - \
            byte_int(headers_byte_length) - int(16)
        payload = message[12 + byte_int(headers_byte_length):
                          12 + byte_int(headers_byte_length) + payload_length]
        message_crc = message[12 + byte_int(headers_byte_length) +
                              payload_length: 12 +
                              byte_int(headers_byte_length) +
                              payload_length + 4]

        if not validate_crc(total_byte_length + headers_byte_length,
                            prelude_crc):
            raise CRCValidationError(
                {"Checksum Mismatch, MessageCRC of " +
                 str(calculate_crc(total_byte_length +
                                   headers_byte_length)) +
                 " does not equal expected CRC of " +
                 str(byte_int(prelude_crc))})

        if not validate_crc(message[0:len(message)-4], message_crc):
            raise CRCValidationError(
                {"Checksum Mismatch, MessageCRC of " +
                 str(calculate_crc(message)) +
                 " does not equal expected CRC of " +
                 str(byte_int(message_crc))})

        header_map = self.__extract_header(header, byte_int(headers_byte_length))

        if header_map["message-type"] == EVENT:
            # Parse message only when event-type is Records,
            # Progress, Stats. Break the loop if event type is End
            # Do nothing if event type is Cont
            if header_map["event-type"] == EVENT_RECORDS or \
               header_map["event-type"] == EVENT_PROGRESS or \
               header_map["event-type"] == EVENT_STATS:
                self.__parse_message(header_map, payload,
                                     payload_length, rec)

            if header_map["event-type"] == EVENT_END:
                end_status = True
        if header_map["message-type"] == ERROR:
            self.__parse_message(header_map, payload, payload_length, rec)
            end_status = True
        return end_status

    def __read(self, num_bytes):
        """
        extract each record from the response body ... and buffer it.
        send only up to requested bytes such as message[:num_bytes]
        rest is buffered and added to the next iteration.
        """
        if len(self.remaining_bytes) == 0:
            res = self.__extract_message()
            if len(res) == 0:
                return b''
            else:
                self.remaining_bytes = res

        if num_bytes < len(self.remaining_bytes):
            result = self.remaining_bytes[:num_bytes]
            del self.remaining_bytes[:num_bytes]
            return result
        else:
            left_in_buffer = self.remaining_bytes[:len(self.remaining_bytes)]
            del self.remaining_bytes[:len(left_in_buffer)]
            return left_in_buffer

    def stream(self, num_bytes):
        """
        streams the response
        """
        while True:
            x = self.__read(num_bytes)
            if x == b'':
                break
            elif len(x) < num_bytes:
                x += self.__read(num_bytes-len(x))
            yield x.decode('utf-8') if isinstance(x, bytearray) else x
