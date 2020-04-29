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
minio.select.options
~~~~~~~~~~~~~~~

This module implements the SelectOption definition for SelectObject API.

:copyright: (c) 2019 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""


class CSVInput:
    """
    CSVInput: Input Format as CSV.
    """

    def __init__(self, file_header_info=None, record_delimiter="\n",
                 field_delimiter=",", quote_character='"',
                 quote_escape_character='"', comments="#",
                 allow_quoted_record_delimiter=False):
        if file_header_info not in [None, "USE", "IGNORE", "NONE"]:
            ValueError("invalid file header info {0}".format(file_header_info))

        self.file_header_info = file_header_info
        self.record_delimiter = record_delimiter
        self.field_delimiter = field_delimiter
        self.quote_character = quote_character
        self.quote_escape_character = quote_escape_character
        self.comments = comments
        self.allow_quoted_record_delimiter = allow_quoted_record_delimiter


class JSONInput:
    """
    JSONInput: Input format as JSON.
    """

    def __init__(self, json_type=None):
        if json_type not in [None, "DOCUMENT", "LINES"]:
            ValueError("invalid type {0}".format(json_type))

        self.json_type = json_type


class ParquetInput:
    """
    ParquetInput: Input format as Parquet
    """


class InputSerialization:
    """
    InputSerialization: nput Format.
    """

    def __init__(self, compression_type="NONE", csv=None, json=None,
                 parquet=None):
        if compression_type not in ["NONE", "GZIP", "BZIP2"]:
            ValueError("invalid compression type {0}".format(compression_type))

        self.compression_type = compression_type
        if (csv is not None) ^ (json is not None) ^ (parquet is not None):
            self.csv = csv
            self.json = json
            self.parquet = parquet
        else:
            ValueError(
                "only one csv, json or parquet input serialization "
                "must be provided"
            )


class CSVOutput:
    """
    CSVOutput: Output as CSV.

    """

    def __init__(self, quote_fields="ASNEEDED", record_delimiter="\n",
                 field_delimiter=",", quote_character='"',
                 quote_escape_character='"'):
        if quote_fields not in ["ALWAYS", "ASNEEDED"]:
            ValueError("invalid quote fields {0}".format(quote_fields))
        self.quote_fields = quote_fields
        self.record_delimiter = record_delimiter
        self.field_delimiter = field_delimiter
        self.quote_character = quote_character
        self.quote_escape_character = quote_escape_character


class JSONOutput:
    """
    JSONOutput- Output as JSON.
    """

    def __init__(self, record_delimiter="\n"):
        self.record_delimiter = record_delimiter


class OutputSerialization:
    """
    OutputSerialization: Output Format.
    """

    def __init__(self, csv=None, json=None):
        if (csv is not None) ^ (json is not None):
            self.csv = csv
            self.json = json
        else:
            ValueError("csv or json output serialization must be provided")


class RequestProgress:
    """
    RequestProgress: Sends progress message.
    """

    def __init__(self, enabled=False):
        self.enabled = enabled


class SelectObjectOptions:
    """
    SelectObjectOptions: Options for select object
    """

    def __init__(self, expression, input_serialization,
                 output_serialization, request_progress):
        self.expression = expression
        self.input_serialization = input_serialization
        self.output_serialization = output_serialization
        self.request_progress = request_progress
