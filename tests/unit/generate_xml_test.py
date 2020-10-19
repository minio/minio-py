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

from minio.definitions import Part
from minio.xml_marshal import marshal_complete_multipart


class GenerateRequestTest(TestCase):
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
            Part(1, 'a54357aff0632cce46d942af68356b38'),
            Part(2, '0c78aef83f66abc1fa1e8477f296d394'),
            Part(3, 'acbd18db4cc2f85cedef654fccc4a4d8'),
        ]
        actual_string = marshal_complete_multipart(etags)
        eq_(expected_string, actual_string)
