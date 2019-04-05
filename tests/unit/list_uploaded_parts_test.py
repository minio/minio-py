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

from nose.tools import eq_
from unittest import TestCase

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT

from .minio_mocks import MockResponse, MockConnection

class ListPartsTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_parts_works(self, mock_connection):
        mock_data = '''<?xml version="1.0"?>
                       <ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                         <Bucket>bucket</Bucket>
                         <Key>go1.4.2</Key>
                         <UploadId>ntWSjzBytPT2xKLaMRonzXncsO10EH4Fc-Iq2-4hG-ulRYB</UploadId>
                         <Initiator>
                           <ID>minio</ID>
                           <DisplayName>minio</DisplayName>
                         </Initiator>
                         <Owner>
                           <ID>minio</ID>
                           <DisplayName>minio</DisplayName>
                         </Owner>
                         <StorageClass>STANDARD</StorageClass>
                         <PartNumberMarker>0</PartNumberMarker>
                         <NextPartNumberMarker>0</NextPartNumberMarker>
                         <MaxParts>1000</MaxParts>
                         <IsTruncated>false</IsTruncated>
                       </ListPartsResult>
                    '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET',
                         'https://localhost:9000/bucket/key?max-parts=1000&uploadId=upload_id',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data))

        client = Minio('localhost:9000')
        part_iter = client._list_object_parts('bucket', 'key', 'upload_id')
        parts = []
        for part in part_iter:
            parts.append(part)
        eq_(0, len(parts))

    @mock.patch('urllib3.PoolManager')
    def test_list_object_parts_works(self, mock_connection):
        mock_data = '''<?xml version="1.0"?>
                       <ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                         <Bucket>bucket</Bucket>
                         <Key>go1.4.2</Key>
                         <UploadId>ntWSjzBytPT2xKLaMRonzXncsO10EH4Fc-Iq2-4hG-ulRYB</UploadId>
                         <Initiator>
                           <ID>minio</ID>
                           <DisplayName>minio</DisplayName>
                         </Initiator>
                         <Owner>
                           <ID>minio</ID>
                           <DisplayName>minio</DisplayName>
                         </Owner>
                         <StorageClass>STANDARD</StorageClass>
                         <PartNumberMarker>0</PartNumberMarker>
                         <NextPartNumberMarker>0</NextPartNumberMarker>
                         <MaxParts>1000</MaxParts>
                         <IsTruncated>false</IsTruncated>
                         <Part>
                           <PartNumber>1</PartNumber>
                           <ETag>79b281060d337b9b2b84ccf390adcf74</ETag>
                           <LastModified>2015-06-03T03:12:34.756Z</LastModified>
                           <Size>5242880</Size>
                         </Part>
                         <Part>
                           <PartNumber>2</PartNumber>
                           <ETag>79b281060d337b9b2b84ccf390adcf74</ETag>
                           <LastModified>2015-06-03T03:12:34.756Z</LastModified>
                           <Size>5242880</Size>
                         </Part>
                       </ListPartsResult>
                    '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(MockResponse('GET',
                                                  'https://localhost:9000/bucket/key?max-parts=1000&uploadId=upload_id',
                                                  {'User-Agent': _DEFAULT_USER_AGENT}, 200,
                                                  content=mock_data))
        client = Minio('localhost:9000')
        part_iter = client._list_object_parts('bucket', 'key', 'upload_id')

        parts = []
        for part in part_iter:
            parts.append(part)
        eq_(2, len(parts))

    @mock.patch('urllib3.PoolManager')
    def test_list_objects_works(self, mock_connection):
        mock_data1 = '''<?xml version="1.0"?>
                        <ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                          <Bucket>bucket</Bucket>
                          <Key>go1.4.2</Key>
                          <UploadId>ntWSjzBytPT2xKLaMRonzXncsO10EH4Fc-Iq2-4hG-ulRYB</UploadId>
                          <Initiator>
                            <ID>minio</ID>
                            <DisplayName>minio</DisplayName>
                          </Initiator>
                          <Owner>
                            <ID>minio</ID>
                            <DisplayName>minio</DisplayName>
                          </Owner>
                          <StorageClass>STANDARD</StorageClass>
                          <PartNumberMarker>0</PartNumberMarker>
                          <NextPartNumberMarker>2</NextPartNumberMarker>
                          <MaxParts>1000</MaxParts>
                          <IsTruncated>true</IsTruncated>
                          <Part>
                            <PartNumber>1</PartNumber>
                            <ETag>79b281060d337b9b2b84ccf390adcf74</ETag>
                            <LastModified>2015-06-03T03:12:34.756Z</LastModified>
                            <Size>5242880</Size>
                          </Part>
                          <Part>
                            <PartNumber>2</PartNumber>
                            <ETag>79b281060d337b9b2b84ccf390adcf74</ETag>
                            <LastModified>2015-06-03T03:12:34.756Z</LastModified>
                            <Size>5242880</Size>
                          </Part>
                        </ListPartsResult>
                        '''
        mock_data2 = '''<?xml version="1.0"?>
                        <ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                          <Bucket>bucket</Bucket>
                          <Key>go1.4.2</Key>
                          <UploadId>ntWSjzBytPT2xKLaMRonzXncsO10EH4Fc-Iq2-4hG-ulRYB</UploadId>
                          <Initiator>
                            <ID>minio</ID>
                            <DisplayName>minio</DisplayName>
                          </Initiator>
                          <Owner>
                            <ID>minio</ID>
                            <DisplayName>minio</DisplayName>
                          </Owner>
                          <StorageClass>STANDARD</StorageClass>
                          <PartNumberMarker>0</PartNumberMarker>
                          <NextPartNumberMarker>0</NextPartNumberMarker>
                          <MaxParts>1000</MaxParts>
                          <IsTruncated>false</IsTruncated>
                          <Part>
                            <PartNumber>3</PartNumber>
                            <ETag>79b281060d337b9b2b84ccf390adcf74</ETag>
                            <LastModified>2015-06-03T03:12:34.756Z</LastModified>
                            <Size>5242880</Size>
                          </Part>
                          <Part>
                            <PartNumber>4</PartNumber>
                            <ETag>79b281060d337b9b2b84ccf390adcf74</ETag>
                            <LastModified>2015-06-03T03:12:34.756Z</LastModified>
                            <Size>5242880</Size>
                          </Part>
                        </ListPartsResult>
                     '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET',
                         'https://localhost:9000/bucket/key?max-parts=1000&uploadId=upload_id',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data1))


        client = Minio('localhost:9000')
        part_iter = client._list_object_parts('bucket', 'key', 'upload_id')

        parts = []
        for part in part_iter:
            mock_server.mock_add_request(
                MockResponse('GET',
                             'https://localhost:9000/bucket/key?max-parts=1000&part-number-marker=2&uploadId=upload_id',
                             {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data2))
            parts.append(part)
        eq_(4, len(parts))
