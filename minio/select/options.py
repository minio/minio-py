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

from .helpers import (SQL)

class CSVInput:
    """
    CSVInput: Input Format as CSV.
    """
    def __init__(self, FileHeaderInfo=None, RecordDelimiter="\n",
                 FieldDelimiter=",", QuoteCharacter='"',
                 QuoteEscapeCharacter='"', Comments="#",
                 AllowQuotedRecordDelimiter=False):
        self.FileHeaderInfo = FileHeaderInfo
        self.RecordDelimiter = RecordDelimiter
        self.FieldDelimiter = FieldDelimiter
        self.QuoteCharacter = QuoteCharacter
        self.QuoteEscapeCharacter = QuoteEscapeCharacter
        self.Comments = Comments
        self.AllowQuotedRecordDelimiter = AllowQuotedRecordDelimiter

class JSONInput:
    """
    JSONInput: Input format as JSON.
    """
    def __init__(self, Type=None):
        self.Type = Type


class ParquetInput:
    """
    ParquetInput: Input format as Parquet
    """


class InputSerialization:
    """
    InputSerialization: nput Format.
    """
    def __init__(self, compression_type="NONE", csv=None, json=None, par=None):
        self.compression_type = compression_type
        self.csv_input = csv
        self.json_input = json
        self.parquet_input = par


class CSVOutput:
    """
    CSVOutput: Output as CSV.

    """
    def __init__(self, QuoteFields="ASNEEDED", RecordDelimiter="\n",
                 FieldDelimiter=",", QuoteCharacter='"',
                 QuoteEscapeCharacter='"'):
        self.QuoteFields = QuoteFields
        self.RecordDelimiter = RecordDelimiter
        self.FieldDelimiter = FieldDelimiter
        self.QuoteCharacter = QuoteCharacter
        self.QuoteEscapeCharacter = QuoteEscapeCharacter


class JsonOutput:
    """
    JsonOutput- Output as JSON.
    """
    def __init__(self, RecordDelimiter="\n"):
        self.RecordDelimiter = RecordDelimiter


class OutputSerialization:
    """
    OutputSerialization: Output Format.
    """
    def __init__(self,  csv=None, json=None):
        self.csv_output = csv
        self.json_output = json


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
    expression_type = SQL

    def __init__(self, expression, input_serialization,
                 output_serialization, request_progress):
        self.expression = expression
        self.in_ser = input_serialization
        self.out_ser = output_serialization
        self.req_progress = request_progress
