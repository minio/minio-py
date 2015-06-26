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
from nose.tools import eq_, timed

from minio import minio
from .minio_mocks import MockResponse

__author__ = 'minio'


class ListObjectsTest(TestCase):
    @mock.patch('requests.get')
    def test_empty_list_objects_works(self, mock_request):
        mock_data = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <Name>bucket</Name>
  <Prefix/>
  <Marker/>
  <MaxKeys>1000</MaxKeys>
  <Delimiter/>
  <IsTruncated>true</IsTruncated>
</ListBucketResult>
        '''
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data)
        client = minio.Minio('http://localhost:9000')
        bucket_iter = client.list_objects('bucket')
        buckets = []
        for bucket in bucket_iter:
            buckets.append(bucket)
        eq_(0, len(buckets))

    @timed(1)
    @mock.patch('requests.get')
    def test_list_objects_works(self, mock_request):
        mock_data = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
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
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data)
        client = minio.Minio('http://localhost:9000')
        bucket_iter = client.list_objects('bucket')
        buckets = []
        for bucket in bucket_iter:
            # cause an xml exception and fail if we try retrieving again
            mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content='')
            buckets.append(bucket)

        eq_(2, len(buckets))

    @timed(1)
    @mock.patch('requests.get')
    def test_list_objects_works(self, mock_request):
        mock_data1 = '''<?xml version="1.0"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <Name>bucket</Name>
  <Prefix/>
  <Marker>marker</Marker>
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
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
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
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data1)
        client = minio.Minio('http://localhost:9000')
        bucket_iter = client.list_objects('bucket')
        buckets = []
        for bucket in bucket_iter:
            mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket?marker=marker', {}, 200,
                                                     content=mock_data2)
            buckets.append(bucket)

        eq_(4, len(buckets))
