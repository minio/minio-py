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
        expected_string = b'<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' \
                          b'<LocationConstraint>region</LocationConstraint></CreateBucketConfiguration>'
        actual_string = xml_marshal_bucket_constraint('region')
        eq_(expected_string, actual_string)

    def test_generate_complete_multipart_upload(self):
        expected_string = b'<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Part>' \
                          b'<PartNumber>1</PartNumber><ETag>"a54357aff0632cce46d942af68356b38"</ETag></Part>' \
                          b'<Part><PartNumber>2</PartNumber><ETag>"0c78aef83f66abc1fa1e8477f296d394"</ETag>' \
                          b'</Part><Part><PartNumber>3</PartNumber><ETag>"acbd18db4cc2f85cedef654fccc4a4d8"' \
                          b'</ETag></Part></CompleteMultipartUpload>'
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
        expected_string = b'<SelectObjectContentRequest><Expression>select * from s3object</Expression>' \
                          b'<ExpressionType>SQL</ExpressionType><InputSerialization>' \
                          b'<CompressionType>NONE</CompressionType>' \
                          b'<CSV><FileHeaderInfo>USE</FileHeaderInfo><RecordDelimiter>\n</RecordDelimiter><FieldDelimiter>,</FieldDelimiter>' \
                          b'<QuoteCharacter>"</QuoteCharacter><QuoteEscapeCharacter>"</QuoteEscapeCharacter><Comments>#</Comments>' \
                          b'<AllowQuotedRecordDelimiter>false</AllowQuotedRecordDelimiter></CSV></InputSerialization>' \
                          b'<OutputSerialization><CSV><QuoteFields>ASNEEDED</QuoteFields>' \
                          b'<RecordDelimiter>\n</RecordDelimiter><FieldDelimiter>,</FieldDelimiter>' \
                          b'<QuoteCharacter>"</QuoteCharacter><QuoteEscapeCharacter>"</QuoteEscapeCharacter></CSV></OutputSerialization>' \
                          b'<RequestProgress><Enabled>true</Enabled></RequestProgress></SelectObjectContentRequest>'

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
                             AllowQuotedRecordDelimiter="FALSE",
                             ),
                ),

            output_serialization=OutputSerialization(
                csv=CSVOutput(QuoteFields="ASNEEDED",
                              RecordDelimiter="\n",
                              FieldDelimiter=",",
                              QuoteCharacter='"',
                              QuoteEscapeCharacter='"',)
                                ),
            request_progress=RequestProgress(
                enabled="TRUE"
                )
            )
        actual_string = xml_marshal_select(options)
        eq_(expected_string, actual_string)
