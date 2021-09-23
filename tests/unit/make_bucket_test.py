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

from unittest import TestCase

import mock

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT
from minio.error import S3Error

from .helpers import generate_error
from .minio_mocks import MockConnection, MockResponse


class MakeBucket(TestCase):
    def test_bucket_is_string(self):
        client = Minio('localhost:9000')
        self.assertRaises(TypeError, client.make_bucket, 1234)

    def test_bucket_is_not_empty_string(self):
        client = Minio('localhost:9000')
        self.assertRaises(ValueError, client.make_bucket, '  \t \n  ')

    @mock.patch('urllib3.PoolManager')
    def test_make_bucket_works(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('PUT',
                         'https://localhost:9000/hello',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         200)
        )
        Minio('localhost:9000')

    @mock.patch('urllib3.PoolManager')
    def test_make_bucket_throws_fail(self, mock_connection):
        error_xml = generate_error('code', 'message', 'request_id',
                                   'host_id', 'resource', 'bucket',
                                   'object')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('PUT',
                         'https://localhost:9000/hello',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         409,
                         response_headers={"Content-Type": "application/xml"},
                         content=error_xml.encode())
        )
        client = Minio('localhost:9000')
        self.assertRaises(S3Error, client.make_bucket, 'hello')
