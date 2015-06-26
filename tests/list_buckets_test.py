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
from datetime import datetime

import mock

from nose.tools import eq_
import pytz

from minio import minio
from .minio_mocks import MockResponse

__author__ = 'minio'


class ListBucketsTest(TestCase):
    @mock.patch('requests.get')
    def test_empty_list_buckets_works(self, mock_request):
        mock_data = '<ListAllMyBucketsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01"><Buckets>' \
                    '</Buckets><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner></ListAllMyBucketsResult>'
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/', {}, 200, content=mock_data)
        client = minio.Minio('http://localhost:9000')
        buckets = client.list_buckets()
        eq_([], buckets)

    @mock.patch('requests.get')
    def test_list_buckets_works(self, mock_request):
        mock_data = '<ListAllMyBucketsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01"><Buckets>' \
                    '<Bucket><Name>hello</Name><CreationDate>2015-06-22T23:07:43.240Z</CreationDate></Bucket><Bucket>' \
                    '<Name>world</Name><CreationDate>2015-06-22T23:07:56.766Z</CreationDate></Bucket>' \
                    '</Buckets><Owner><ID>minio</ID><DisplayName>minio</DisplayName></Owner></ListAllMyBucketsResult>'
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/', {}, 200, content=mock_data)
        client = minio.Minio('http://localhost:9000')
        buckets = client.list_buckets()

        eq_(2, len(buckets))
        eq_('hello', buckets[0].name)
        eq_(datetime(2015, 6, 22, 23, 7, 43, 240000, pytz.utc), buckets[0].creation_date)
        eq_('world', buckets[1].name)
        eq_(datetime(2015, 6, 22, 23, 7, 56, 766000, pytz.utc), buckets[1].creation_date)
