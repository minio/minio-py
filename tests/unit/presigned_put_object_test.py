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

from datetime import timedelta
from unittest import TestCase

from nose.tools import raises

from minio import Minio


class PresignedPutObjectTest(TestCase):
    @raises(TypeError)
    def test_object_is_string(self):
        client = Minio('localhost:9000')
        client.presigned_put_object('hello', 1234)

    @raises(ValueError)
    def test_object_is_not_empty_string(self):
        client = Minio('localhost:9000')
        client.presigned_put_object('hello', ' \t \n ')

    @raises(ValueError)
    def test_expiry_limit(self):
        client = Minio('localhost:9000')
        client.presigned_put_object('hello', 'key', expires=timedelta(days=8))
