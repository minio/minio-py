# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2016 MinIO, Inc.
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

import mock
import itertools

from unittest import TestCase
from nose.tools import raises

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT
from minio.error import InvalidBucketError

from .minio_mocks import MockResponse, MockConnection

class RemoveObjectsTest(TestCase):
    @raises(TypeError)
    def test_object_is_non_string_iterable_1(self):
        client = Minio('localhost:9000')
        for err in client.remove_objects('hello', 1234):
            print(err)

    @raises(TypeError)
    def test_object_is_non_string_iterable_2(self):
        client = Minio('localhost:9000')
        for err in client.remove_objects('hello', u'abc'):
            print(err)

    @raises(TypeError)
    def test_object_is_non_string_iterable_3(self):
        client = Minio('localhost:9000')
        for err in client.remove_objects('hello', b'abc'):
            print(err)

    @raises(InvalidBucketError)
    def test_bucket_invalid_name(self):
        client = Minio('localhost:9000')
        for err in client.remove_objects('ABCD', 'world'):
            print(err)

    @mock.patch('urllib3.PoolManager')
    def test_object_is_list(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('POST',
                         'https://localhost:9000/hello/?delete=',
                         {'Content-Length': 95,
                          'User-Agent': _DEFAULT_USER_AGENT,
                          'Content-Md5': u'5Tg5SmU9Or43L4+iIyfPrQ=='}, 200,
                         content='<Delete/>')
        )
        client = Minio('localhost:9000')
        for err in client.remove_objects('hello', ["Ab", "c"]):
            print(err)

    @mock.patch('urllib3.PoolManager')
    def test_object_is_tuple(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('POST',
                         'https://localhost:9000/hello/?delete=',
                         {'Content-Length': 95,
                          'User-Agent': _DEFAULT_USER_AGENT,
                          'Content-Md5': u'5Tg5SmU9Or43L4+iIyfPrQ=='}, 200,
                         content='<Delete/>')
        )
        client = Minio('localhost:9000')
        for err in client.remove_objects('hello', ('Ab', 'c')):
            print(err)

    @mock.patch('urllib3.PoolManager')
    def test_object_is_iterator(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('POST',
                         'https://localhost:9000/hello/?delete=',
                         {'Content-Length': 95,
                          'User-Agent': _DEFAULT_USER_AGENT,
                          'Content-Md5': u'5Tg5SmU9Or43L4+iIyfPrQ=='}, 200,
                         content='<Delete/>')
        )
        client = Minio('localhost:9000')
        it = itertools.chain(('Ab', 'c'))
        for err in client.remove_objects('hello', it):
            print(err)
