# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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

import unittest.mock as mock
from unittest import TestCase

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT
from minio.error import S3Error

from .minio_mocks import MockConnection, MockResponse


class BucketExists(TestCase):
    def test_bucket_is_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(TypeError):
            client.bucket_exists(bucket_name=1234)

    def test_bucket_is_not_empty_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.bucket_exists(bucket_name='  \t \n  ')

    def test_bucket_exists_invalid_name(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.bucket_exists(bucket_name='AB*CD')

    @mock.patch('urllib3.PoolManager')
    def test_bucket_exists_bad_request(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('HEAD',
                         'https://localhost:9000/hello',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         400)
        )
        client = Minio(endpoint='localhost:9000')
        kwargs = {"bucket_name": 'hello'}
        self.assertRaises(S3Error, client.bucket_exists, **kwargs)

    @mock.patch('urllib3.PoolManager')
    def test_bucket_exists_works(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('HEAD',
                         'https://localhost:9000/hello',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         200)
        )
        client = Minio(endpoint='localhost:9000')
        result = client.bucket_exists(bucket_name='hello')
        self.assertTrue(result)
        mock_server.mock_add_request(
            MockResponse('HEAD',
                         'https://localhost:9000/goodbye',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         404)
        )
        false_result = client.bucket_exists(bucket_name='goodbye')
        self.assertFalse(false_result)
