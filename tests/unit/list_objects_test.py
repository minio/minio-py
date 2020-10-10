# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015-2020 MinIO, Inc.
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

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT

from .minio_mocks import MockConnection, MockResponse


class ListObjectsTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_objects_works(self, mock_connection):
        mock_data = '''<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix></Prefix>
  <KeyCount>0</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <Delimiter></Delimiter>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>'''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                "GET",
                "https://localhost:9000/bucket?delimiter=&list-type=2"
                "&max-keys=1000&prefix=",
                {"User-Agent": _DEFAULT_USER_AGENT},
                200,
                content=mock_data.encode(),
            ),
        )
        client = Minio('localhost:9000')
        object_iter = client.list_objects('bucket', recursive=True)
        objects = []
        for obj in object_iter:
            objects.append(obj)
        eq_(0, len(objects))

    @timed(1)
    @mock.patch('urllib3.PoolManager')
    def test_list_objects_works(self, mock_connection):
        mock_data = '''<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix></Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>6/f/9/6f9898076bb08572403f95dbb86c5b9c85e1e1b3</Key>
    <LastModified>2016-11-27T07:55:53.000Z</LastModified>
    <ETag>&quot;5d5512301b6b6e247b8aec334b2cf7ea&quot;</ETag>
    <Size>493</Size>
    <StorageClass>REDUCED_REDUNDANCY</StorageClass>
  </Contents>
  <Contents>
    <Key>b/d/7/bd7f6410cced55228902d881c2954ebc826d7464</Key>
    <LastModified>2016-11-27T07:10:27.000Z</LastModified>
    <ETag>&quot;f00483d523ffc8b7f2883ae896769d85&quot;</ETag>
    <Size>493</Size>
    <StorageClass>REDUCED_REDUNDANCY</StorageClass>
  </Contents>
</ListBucketResult>'''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                "GET",
                "https://localhost:9000/bucket?delimiter=%2F&list-type=2"
                "&max-keys=1000&prefix=",
                {"User-Agent": _DEFAULT_USER_AGENT},
                200,
                content=mock_data.encode(),
            ),
        )
        client = Minio('localhost:9000')
        objects_iter = client.list_objects('bucket')
        objects = []
        for obj in objects_iter:
            objects.append(obj)

        eq_(2, len(objects))
