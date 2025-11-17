# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
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
from unittest import TestCase, mock

from minio import Minio
from minio.helpers import HTTPQueryDict


class PresignedGetObjectTest(TestCase):
    def test_object_is_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(TypeError):
            client.presigned_get_object(bucket_name='hello', object_name=1234)

    def test_object_is_not_empty_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.presigned_get_object(
                bucket_name='hello',
                object_name=' \t \n ',
            )

    def test_expiry_limit(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.presigned_get_object(
                bucket_name='hello',
                object_name='key',
                expires=timedelta(days=8),
            )

    def test_can_include_response_headers(self):
        client = Minio(
            endpoint='localhost:9000',
            access_key='my_access_key',
            secret_key='my_secret_key',
            secure=True,
        )
        client._get_region = mock.Mock(return_value='us-east-1')
        r = client.presigned_get_object(
            bucket_name='mybucket',
            object_name='myfile.pdf',
            extra_query_params=HTTPQueryDict({
                'Response-Content-Type': 'application/pdf',
                'Response-Content-Disposition': 'inline;  filename="test.pdf"'
            }),
        )
        self.assertIn('inline', r)
        self.assertIn('test.pdf', r)
        self.assertIn('application%2Fpdf', r)
