# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 MinIO, Inc.
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

import mock
import pytz

from nose.tools import eq_
from unittest import TestCase
from datetime import datetime

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT

from .minio_mocks import MockResponse, MockConnection

class ListBucketsTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_buckets_works(self, mock_connection):
        mock_data = '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets>' \
                    '</Buckets><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner></ListAllMyBucketsResult>'
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(MockResponse('GET', 'https://localhost:9000/',
                                                  {'User-Agent': _DEFAULT_USER_AGENT},
                                                  200, content=mock_data))
        client = Minio('localhost:9000')
        buckets = client.list_buckets()
        count = 0
        for bucket in buckets:
            count += 1
        eq_(0, count)

    @mock.patch('urllib3.PoolManager')
    def test_list_buckets_works(self, mock_connection):
        mock_data = '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets>' \
                    '<Bucket><Name>hello</Name><CreationDate>2015-06-22T23:07:43.240Z</CreationDate></Bucket><Bucket>' \
                    '<Name>world</Name><CreationDate>2015-06-22T23:07:56.766Z</CreationDate></Bucket>' \
                    '</Buckets><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner></ListAllMyBucketsResult>'
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(MockResponse('GET', 'https://localhost:9000/',
                                                  {'User-Agent': _DEFAULT_USER_AGENT},
                                                  200, content=mock_data))
        client = Minio('localhost:9000')
        buckets = client.list_buckets()
        buckets_list = []
        count = 0
        for bucket in buckets:
            count += 1
            buckets_list.append(bucket)
        eq_(2, count)
        eq_('hello', buckets_list[0].name)
        eq_(datetime(2015, 6, 22, 23, 7, 43, 240000, pytz.utc), buckets_list[0].creation_date)
        eq_('world', buckets_list[1].name)
        eq_(datetime(2015, 6, 22, 23, 7, 56, 766000, pytz.utc), buckets_list[1].creation_date)
