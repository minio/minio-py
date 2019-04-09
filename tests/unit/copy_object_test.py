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
from minio.error import InvalidBucketError
from minio.copy_conditions import CopyConditions

class CopyObjectTest(TestCase):
    @raises(TypeError)
    def test_object_is_string(self):
        client = Minio('localhost:9000')
        client.copy_object('hello', 12, 12)

    @raises(ValueError)
    def test_object_is_not_empty_string(self):
        client = Minio('localhost:9000')
        client.copy_object('hello', ' \t \n ', '')

    @raises(InvalidBucketError)
    def test_length_is_string(self):
        client = Minio('localhost:9000')
        client.copy_object('..hello', '1', '/testbucket/object')

class CopyConditionTest(TestCase):
    @raises(ValueError)
    def test_match_etag_is_not_empty(self):
        conds = CopyConditions()
        conds.set_match_etag('')

    @raises(ValueError)
    def test_match_etag_is_not_empty_except(self):
        conds = CopyConditions()
        conds.set_match_etag_except('')

    @raises(AttributeError)
    def test_unmodified_since(self):
        conds = CopyConditions()
        conds.set_unmodified_since('')

    @raises(AttributeError)
    def test_modified_since(self):
        conds = CopyConditions()
        conds.set_modified_since('')
