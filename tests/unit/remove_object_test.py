# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
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

from unittest import TestCase, mock

from minio import Minio
from minio.helpers import _DEFAULT_USER_AGENT

from .minio_mocks import MockConnection, MockResponse


class StatObject(TestCase):
    def test_object_is_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(TypeError):
            client.remove_object(bucket_name='hello', object_name=1234)

    def test_object_is_not_empty_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.remove_object(
                bucket_name='hello',
                object_name='  \t \n  ',
            )

    def test_remove_bucket_invalid_name(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.remove_object(
                bucket_name='AB*CD',
                object_name='world',
            )

    @mock.patch('urllib3.PoolManager')
    def test_remove_object_works(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/hello/world',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 204)
        )
        client = Minio(endpoint='localhost:9000')
        client.remove_object(
            bucket_name='hello',
            object_name='world',
        )
