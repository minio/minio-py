# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import TestCase

import mock
from nose.tools import raises

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT

from .minio_mocks import MockConnection, MockResponse


class StatObject(TestCase):
    @raises(TypeError)
    def test_object_is_string(self):
        client = Minio('localhost:9000')
        client.stat_object('hello', 1234)

    @raises(ValueError)
    def test_object_is_not_empty_string(self):
        client = Minio('localhost:9000')
        client.stat_object('hello', '  \t \n  ')

    @raises(ValueError)
    def test_stat_object_invalid_name(self):
        client = Minio('localhost:9000')
        client.stat_object('AB#CD', 'world')

    @mock.patch('urllib3.PoolManager')
    def test_stat_object_works(self, mock_connection):
        mock_headers = {
            'content-type': 'application/octet-stream',
            'last-modified': 'Fri, 26 Jun 2015 19:05:37 GMT',
            'content-length': 11,
            'etag': '5eb63bbbe01eeed093cb22bb8f5acdc3'
        }
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('HEAD',
                         'https://localhost:9000/hello/world',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200,
                         response_headers=mock_headers)
        )
        client = Minio('localhost:9000')
        client.stat_object('hello', 'world')
