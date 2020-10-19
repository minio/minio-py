# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2020 MinIO, Inc.
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

"""Request/response of PutBucketReplication and GetBucketReplication APIs."""

from __future__ import absolute_import

from abc import ABCMeta

from .xml import Element, SubElement

COMPRESSION_TYPE_NONE = "NONE"
COMPRESSION_TYPE_GZIP = "GZIP"
COMPRESSION_TYPE_BZIP2 = "BZIP2"

FILE_HEADER_INFO_USE = "USE"
FILE_HEADER_INFO_IGNORE = "IGNORE"
FILE_HEADER_INFO_NONE = "NONE"

JSON_TYPE_DOCUMENT = "DOCUMENT"
JSON_TYPE_LINES = "LINES"

QUOTE_FIELDS_ALWAYS = "ALWAYS"
QUOTE_FIELDS_ASNEEDED = "ASNEEDED"


class InputSerialization:
    """Input serialization."""

    __metaclass__ = ABCMeta

    def __init__(self, compression_type):
        if (
                compression_type is not None and
                compression_type not in [
                    COMPRESSION_TYPE_NONE,
                    COMPRESSION_TYPE_GZIP,
                    COMPRESSION_TYPE_BZIP2,
                ]
        ):
            raise ValueError(
                "compression type must be {0}, {1} or {2}".format(
                    COMPRESSION_TYPE_NONE,
                    COMPRESSION_TYPE_GZIP,
                    COMPRESSION_TYPE_BZIP2,
                ),
            )
        self._compression_type = compression_type

    def toxml(self, element):
        """Convert to XML."""
        if self._compression_type is not None:
            SubElement(element, "CompressionType")
        return element


class CSVInputSerialization(InputSerialization):
    """CSV input serialization."""

    def __init__(self, compression_type=None,
                 allow_quoted_record_delimiter=None, comments=None,
                 field_delimiter=None, file_header_info=None,
                 quote_character=None, quote_escape_character=None,
                 record_delimiter=None):
        super().__init__(compression_type)
        self._allow_quoted_record_delimiter = allow_quoted_record_delimiter
        self._comments = comments
        self._field_delimiter = field_delimiter
        if (
                file_header_info is not None and
                file_header_info not in [
                    FILE_HEADER_INFO_USE,
                    FILE_HEADER_INFO_IGNORE,
                    FILE_HEADER_INFO_NONE,
                ]
        ):
            raise ValueError(
                "file header info must be {0}, {1} or {2}".format(
                    FILE_HEADER_INFO_USE,
                    FILE_HEADER_INFO_IGNORE,
                    FILE_HEADER_INFO_NONE,
                ),
            )
        self._file_header_info = file_header_info
        self._quote_character = quote_character
        self._quote_escape_character = quote_escape_character
        self._record_delimiter = record_delimiter

    def toxml(self, element):
        """Convert to XML."""
        super().toxml(element)
        element = SubElement(element, "CSV")
        if self._allow_quoted_record_delimiter is not None:
            SubElement(
                element,
                "AllowQuotedRecordDelimiter",
                self._allow_quoted_record_delimiter,
            )
        if self._comments is not None:
            SubElement(element, "Comments", self._comments)
        if self._field_delimiter is not None:
            SubElement(element, "FieldDelimiter", self._field_delimiter)
        if self._file_header_info is not None:
            SubElement(element, "FileHeaderInfo", self._file_header_info)
        if self._quote_character is not None:
            SubElement(element, "QuoteCharacter", self._quote_character)
        if self._quote_escape_character is not None:
            SubElement(
                element,
                "QuoteEscapeCharacter",
                self._quote_escape_character,
            )
        if self._record_delimiter is not None:
            SubElement(element, "RecordDelimiter", self._record_delimiter)


class JSONInputSerialization(InputSerialization):
    """JSON input serialization."""

    def __init__(self, compression_type=None, json_type=None):
        super().__init__(compression_type)
        if (
                json_type is not None and
                json_type not in [JSON_TYPE_DOCUMENT, JSON_TYPE_LINES]
        ):
            raise ValueError(
                "json type must be {0} or {1}".format(
                    JSON_TYPE_DOCUMENT, JSON_TYPE_LINES,
                ),
            )
        self._json_type = json_type

    def toxml(self, element):
        """Convert to XML."""
        super().toxml(element)
        element = SubElement(element, "JSON")
        if self._json_type is not None:
            SubElement(element, "Type", self._json_type)


class ParquetInputSerialization(InputSerialization):
    """Parquet input serialization."""

    def __init__(self, compression_type=None):
        super().__init__(compression_type)

    def toxml(self, element):
        """Convert to XML."""
        super().toxml(element)
        return SubElement(element, "Parquet")


class CSVOutputSerialization:
    """CSV output serialization."""

    def __init__(self, field_delimiter=None, quote_character=None,
                 quote_escape_character=None, quote_fields=None,
                 record_delimiter=None):
        self._field_delimiter = field_delimiter
        self._quote_character = quote_character
        self._quote_escape_character = quote_escape_character
        if (
                quote_fields is not None and
                quote_fields not in [
                    QUOTE_FIELDS_ALWAYS, QUOTE_FIELDS_ASNEEDED,
                ]
        ):
            raise ValueError(
                "quote fields must be {0} or {1}".format(
                    QUOTE_FIELDS_ALWAYS, QUOTE_FIELDS_ASNEEDED,
                ),
            )
        self._quote_fields = quote_fields
        self._record_delimiter = record_delimiter

    def toxml(self, element):
        """Convert to XML."""
        element = SubElement(element, "CSV")
        if self._field_delimiter is not None:
            SubElement(element, "FieldDelimiter", self._field_delimiter)
        if self._quote_character is not None:
            SubElement(element, "QuoteCharacter", self._quote_character)
        if self._quote_escape_character is not None:
            SubElement(
                element,
                "QuoteEscapeCharacter",
                self._quote_escape_character,
            )
        if self._quote_fields is not None:
            SubElement(element, "QuoteFields", self._quote_fields)
        if self._record_delimiter is not None:
            SubElement(element, "RecordDelimiter", self._record_delimiter)


class JSONOutputSerialization:
    """JSON output serialization."""

    def __init__(self, record_delimiter=None):
        self._record_delimiter = record_delimiter

    def toxml(self, element):
        """Convert to XML."""
        element = SubElement(element, "JSON")
        if self._record_delimiter is not None:
            SubElement(element, "RecordDelimiter", self._record_delimiter)


class SelectRequest:
    """Select object content request."""

    def __init__(self, expression, input_serialization, output_serialization,
                 request_progress=False, scan_start_range=None,
                 scan_end_range=None):
        self._expession = expression
        if not isinstance(
                input_serialization,
                (
                    CSVInputSerialization,
                    JSONInputSerialization,
                    ParquetInputSerialization,
                ),
        ):
            raise ValueError(
                "input serialization must be CSVInputSerialization, "
                "JSONInputSerialization or ParquetInputSerialization type",
            )
        self._input_serialization = input_serialization
        if not isinstance(
                output_serialization,
                (CSVOutputSerialization, JSONOutputSerialization),
        ):
            raise ValueError(
                "output serialization must be CSVOutputSerialization or "
                "JSONOutputSerialization type",
            )
        self._output_serialization = output_serialization
        self._request_progress = request_progress
        self._scan_start_range = scan_start_range
        self._scan_end_range = scan_end_range

    def toxml(self, element):
        """Convert to XML."""
        element = Element("SelectObjectContentRequest")
        SubElement(element, "Expression", self._expession)
        SubElement(element, "ExpressionType", "SQL")
        self._input_serialization.toxml(
            SubElement(element, "InputSerialization"),
        )
        self._output_serialization.toxml(
            SubElement(element, "OutputSerialization"),
        )
        if self._request_progress:
            SubElement(
                SubElement(element, "RequestProgress"), "Enabled", "true",
            )
        if self._scan_start_range or self._scan_end_range:
            tag = SubElement(element, "ScanRange")
            if self._scan_start_range:
                SubElement(tag, "Start", self._scan_start_range)
            if self._scan_end_range:
                SubElement(tag, "End", self._scan_end_range)
        return element
