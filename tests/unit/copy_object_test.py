# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 MinIO, Inc.
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

from minio import Minio
from minio.commonconfig import CopySource


class CopyObjectTest(TestCase):
    def test_valid_copy_source(self):
        client = Minio('localhost:9000')
        self.assertRaises(
            ValueError,
            client.copy_object, 'hello', '1', '/testbucket/object'
        )

    def test_valid_match_etag(self):
        self.assertRaises(
            ValueError, CopySource, "src-bucket", "src-object", match_etag='')

    def test_not_match_etag(self):
        self.assertRaises(
            ValueError,
            CopySource, "src-bucket", "src-object", not_match_etag=''
        )

    def test_valid_modified_since(self):
        self.assertRaises(
            ValueError,
            CopySource, "src-bucket", "src-object", modified_since=''
        )

    def test_valid_unmodified_since(self):
        self.assertRaises(
            ValueError,
            CopySource, "src-bucket", "src-object", unmodified_since=''
        )
