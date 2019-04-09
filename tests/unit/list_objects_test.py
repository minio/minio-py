# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 MinIO, Inc.
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

from nose.tools import eq_, timed
from unittest import TestCase

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT

from .minio_mocks import MockResponse, MockConnection

class ListObjectsTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_objects_works(self, mock_connection):
        mock_data = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix/>
  <Marker/>
  <IsTruncated>false</IsTruncated>
  <MaxKeys>1000</MaxKeys>
  <Delimiter/>
</ListBucketResult>
        '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(MockResponse('GET',
                                                  'https://localhost:9000/bucket/?max-keys=1000&prefix=',
                                                  {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data))
        client = Minio('localhost:9000')
        bucket_iter = client.list_objects('bucket', recursive=True)
        buckets = []
        for bucket in bucket_iter:
            buckets.append(bucket)
        eq_(0, len(buckets))

    @timed(1)
    @mock.patch('urllib3.PoolManager')
    def test_list_objects_works(self, mock_connection):
        mock_data = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix/>
  <Marker/>
  <MaxKeys>1000</MaxKeys>
  <Delimiter/>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>key1</Key>
    <LastModified>2015-05-05T02:21:15.716Z</LastModified>
    <ETag>5eb63bbbe01eeed093cb22bb8f5acdc3</ETag>
    <Size>11</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>minio</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
  </Contents>
  <Contents>
    <Key>key2</Key>
    <LastModified>2015-05-05T20:36:17.498Z</LastModified>
    <ETag>2a60eaffa7a82804bdc682ce1df6c2d4</ETag>
    <Size>1661</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>minio</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
  </Contents>
</ListBucketResult>
        '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(MockResponse('GET',
                                                  'https://localhost:9000/bucket/?delimiter=%2F&max-keys=1000&prefix=',
                                                  {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data))
        client = Minio('localhost:9000')
        bucket_iter = client.list_objects('bucket')
        buckets = []
        for bucket in bucket_iter:
            # cause an xml exception and fail if we try retrieving again
            mock_server.mock_add_request(MockResponse('GET',
                                                      'https://localhost:9000/bucket/?delimiter=%2F&max-keys=1000&prefix=',
                                                      {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=''))
            buckets.append(bucket)

        eq_(2, len(buckets))

    @timed(1)
    @mock.patch('urllib3.PoolManager')
    def test_list_objects_works_well(self, mock_connection):
        mock_data1 = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix/>
  <Marker />
  <NextMarker>marker</NextMarker>
  <MaxKeys>1000</MaxKeys>
  <Delimiter/>
  <IsTruncated>true</IsTruncated>
  <Contents>
    <Key>key1</Key>
    <LastModified>2015-05-05T02:21:15.716Z</LastModified>
    <ETag>5eb63bbbe01eeed093cb22bb8f5acdc3</ETag>
    <Size>11</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>minio</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
  </Contents>
  <Contents>
    <Key>key2</Key>
    <LastModified>2015-05-05T20:36:17.498Z</LastModified>
    <ETag>2a60eaffa7a82804bdc682ce1df6c2d4</ETag>
    <Size>1661</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>minio</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
  </Contents>
</ListBucketResult>
        '''
        mock_data2 = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix/>
  <Marker/>
  <MaxKeys>1000</MaxKeys>
  <Delimiter/>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>key3</Key>
    <LastModified>2015-05-05T02:21:15.716Z</LastModified>
    <ETag>5eb63bbbe01eeed093cb22bb8f5acdc3</ETag>
    <Size>11</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>minio</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
  </Contents>
  <Contents>
    <Key>key4</Key>
    <LastModified>2015-05-05T20:36:17.498Z</LastModified>
    <ETag>2a60eaffa7a82804bdc682ce1df6c2d4</ETag>
    <Size>1661</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>minio</ID>
      <DisplayName>minio</DisplayName>
    </Owner>
  </Contents>
</ListBucketResult>
        '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(MockResponse('GET',
                                                  'https://localhost:9000/bucket/?max-keys=1000&prefix=',
                                                  {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data1))
        client = Minio('localhost:9000')
        bucket_iter = client.list_objects('bucket', recursive=True)
        buckets = []
        for bucket in bucket_iter:
            url = 'https://localhost:9000/bucket/?marker=marker&max-keys=1000&prefix='
            mock_server.mock_add_request(MockResponse('GET', url,
                                                      {'User-Agent': _DEFAULT_USER_AGENT}, 200,
                                                      content=mock_data2))
            buckets.append(bucket)

        eq_(4, len(buckets))
