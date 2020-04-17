# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016, 2017, 2018, 2019 MinIO, Inc.
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

from unittest import TestCase
from nose.tools import eq_

from minio.definitions import UploadPart
from minio.xml_marshal import (xml_marshal_bucket_constraint,
                               xml_marshal_complete_multipart_upload,
                               xml_marshal_select)
from minio.select.options import (SelectObjectOptions,
                                  CSVInput,
                                  RequestProgress,
                                  InputSerialization,
                                  OutputSerialization,
                                  CSVOutput)


class GenerateRequestTest(TestCase):
    def test_generate_bucket_constraint(self):
        expected_string = (b'<CreateBucketConfiguration '
                           b'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                           b'<LocationConstraint>region</LocationConstraint>'
                           b'</CreateBucketConfiguration>')
        actual_string = xml_marshal_bucket_constraint('region')
        eq_(expected_string, actual_string)

    def test_generate_complete_multipart_upload(self):
        expected_string = (b'<CompleteMultipartUpload '
                           b'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                           b'<Part><PartNumber>1</PartNumber>'
                           b'<ETag>"a54357aff0632cce46d942af68356b38"</ETag>'
                           b'</Part>'
                           b'<Part><PartNumber>2</PartNumber>'
                           b'<ETag>"0c78aef83f66abc1fa1e8477f296d394"</ETag>'
                           b'</Part>'
                           b'<Part><PartNumber>3</PartNumber>'
                           b'<ETag>"acbd18db4cc2f85cedef654fccc4a4d8"</ETag>'
                           b'</Part>'
                           b'</CompleteMultipartUpload>')

        etags = [
            UploadPart('bucket', 'object', 'upload_id', 1,
                       'a54357aff0632cce46d942af68356b38',
                       None, 0),
            UploadPart('bucket', 'object', 'upload_id', 2,
                       '0c78aef83f66abc1fa1e8477f296d394',
                       None, 0),
            UploadPart('bucket', 'object', 'upload_id', 3,
                       'acbd18db4cc2f85cedef654fccc4a4d8',
                       None, 0),
        ]
        actual_string = xml_marshal_complete_multipart_upload(etags)
        eq_(expected_string, actual_string)

    def test_xml_marshal_select(self):
        expected_string = (b'<SelectObjectContentRequest>'
                           b'<Expression>select * from s3object</Expression>'
                           b'<ExpressionType>SQL</ExpressionType>'
                           b'<InputSerialization>'
                           b'<CompressionType>NONE</CompressionType>'
                           b'<CSV><FileHeaderInfo>USE</FileHeaderInfo>'
                           b'<RecordDelimiter>\n</RecordDelimiter>'
                           b'<FieldDelimiter>,</FieldDelimiter>'
                           b'<QuoteCharacter>"</QuoteCharacter>'
                           b'<QuoteEscapeCharacter>"</QuoteEscapeCharacter>'
                           b'<Comments>#</Comments>'
                           b'<AllowQuotedRecordDelimiter>false'
                           b'</AllowQuotedRecordDelimiter></CSV>'
                           b'</InputSerialization>'
                           b'<OutputSerialization><CSV>'
                           b'<QuoteFields>ASNEEDED</QuoteFields>'
                           b'<RecordDelimiter>\n</RecordDelimiter>'
                           b'<FieldDelimiter>,</FieldDelimiter>'
                           b'<QuoteCharacter>"</QuoteCharacter>'
                           b'<QuoteEscapeCharacter>"</QuoteEscapeCharacter>'
                           b'</CSV></OutputSerialization>'
                           b'<RequestProgress>'
                           b'<Enabled>true</Enabled>'
                           b'</RequestProgress>'
                           b'</SelectObjectContentRequest>')

        options = SelectObjectOptions(
            expression="select * from s3object",
            input_serialization=InputSerialization(
                compression_type="NONE",
                csv=CSVInput(FileHeaderInfo="USE",
                             RecordDelimiter="\n",
                             FieldDelimiter=",",
                             QuoteCharacter='"',
                             QuoteEscapeCharacter='"',
                             Comments="#",
                             AllowQuotedRecordDelimiter="FALSE"),
            ),

            output_serialization=OutputSerialization(
                csv=CSVOutput(QuoteFields="ASNEEDED",
                              RecordDelimiter="\n",
                              FieldDelimiter=",",
                              QuoteCharacter='"',
                              QuoteEscapeCharacter='"')
            ),
            request_progress=RequestProgress(
                enabled="TRUE"
            )
        )
        actual_string = xml_marshal_select(options)
        eq_(expected_string, actual_string)
