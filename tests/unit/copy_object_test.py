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

from nose.tools import raises

from minio import Minio
from minio.commonconfig import CopySource


class CopyObjectTest(TestCase):
    @raises(ValueError)
    def test_valid_copy_source(self):
        client = Minio('localhost:9000')
        client.copy_object('hello', '1', '/testbucket/object')

    @raises(ValueError)
    def test_valid_match_etag(self):
        CopySource("src-bucket", "src-object", match_etag='')

    @raises(ValueError)
    def test_not_match_etag(self):
        CopySource("src-bucket", "src-object", not_match_etag='')

    @raises(ValueError)
    def test_valid_modified_since(self):
        CopySource("src-bucket", "src-object", modified_since='')

    @raises(ValueError)
    def test_valid_unmodified_since(self):
        CopySource("src-bucket", "src-object", unmodified_since='')
