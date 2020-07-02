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

import mock
from minio import Minio
from minio.error import InvalidArgumentError


class PresignedPutObjectTest(TestCase):
    @raises(TypeError)
    def test_object_is_string(self):
        client = Minio('localhost:9000')
        client.presigned_put_object('hello', 1234)

    @raises(ValueError)
    def test_object_is_not_empty_string(self):
        client = Minio('localhost:9000')
        client.presigned_put_object('hello', ' \t \n ')

    @raises(InvalidArgumentError)
    def test_expiry_limit(self):
        client = Minio('localhost:9000')
        client.presigned_put_object('hello', 'key', expires=timedelta(days=8))

    def test_endpoint_url(self):
        client = Minio('minio-docker:9000', 'my_access_key',
                       'my_secret_key', secure=True)
        client._get_bucket_region = mock.Mock(return_value='us-east-1')
        url = client.presigned_put_object(
            'bucket', 'key', endpoint_url='http://localhost:9000')
        self.assertRegexpMatches(url, r'^http://localhost:9000/bucket/key\?')
