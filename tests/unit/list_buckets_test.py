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

from datetime import datetime, timezone
from unittest import TestCase, mock

from minio import Minio
from minio.helpers import _DEFAULT_USER_AGENT

from .minio_mocks import MockConnection, MockResponse


class ListBucketsTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_buckets_works(self, mock_connection):
        mock_data = ('<ListAllMyBucketsResult '
                     'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                     '<Buckets></Buckets><Owner><ID>minio</ID><DisplayName>'
                     'minio</DisplayName></Owner></ListAllMyBucketsResult>')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                'GET',
                'https://localhost:9000/?max-buckets=10000',
                {'User-Agent': _DEFAULT_USER_AGENT},
                200,
                content=mock_data.encode(),
            ),
        )
        client = Minio(endpoint='localhost:9000')
        self.assertEqual(0, len(list(client.list_buckets())))

    @mock.patch('urllib3.PoolManager')
    def test_list_buckets_works(self, mock_connection):
        mock_data = ('<ListAllMyBucketsResult '
                     'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                     '<Buckets><Bucket><Name>hello</Name>'
                     '<CreationDate>2015-06-22T23:07:43.240Z</CreationDate>'
                     '</Bucket><Bucket><Name>world</Name>'
                     '<CreationDate>2015-06-22T23:07:56.766Z</CreationDate>'
                     '</Bucket></Buckets><Owner><ID>minio</ID>'
                     '<DisplayName>minio</DisplayName></Owner>'
                     '</ListAllMyBucketsResult>')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                'GET',
                'https://localhost:9000/?max-buckets=10000',
                {'User-Agent': _DEFAULT_USER_AGENT},
                200,
                content=mock_data.encode(),
            ),
        )
        client = Minio(endpoint='localhost:9000')
        buckets = list(client.list_buckets())
        self.assertEqual(2, len(buckets))
        self.assertEqual('hello', buckets[0].name)
        self.assertEqual(
            datetime(2015, 6, 22, 23, 7, 43, 240000, timezone.utc),
            buckets[0].creation_date,
        )
        self.assertEqual('world', buckets[1].name)
        self.assertEqual(
            datetime(2015, 6, 22, 23, 7, 56, 766000, timezone.utc),
            buckets[1].creation_date,
        )
