# Minimal Object Storage Library, (C) 2015 Minio, Inc.
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

from minio import minio
from .minio_mocks import MockConnection, MockResponse

__author__ = 'minio'


class MakeBucket(TestCase):
    @mock.patch('urllib3.connectionpool.connection_from_url')
    def test_make_bucket_works(self, mock_connectionpool):
        mock_connection = MockConnection()
        mock_connection.mock_add_request(MockResponse('PUT', 'http://localhost:9000/hello', {}, 200))
        mock_connectionpool.return_value = mock_connection
        client = minio.Minio('http://localhost:9000')
        client.make_bucket('hello')
