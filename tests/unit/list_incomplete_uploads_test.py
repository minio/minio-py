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

class ListIncompleteUploadsTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_uploads_test(self, mock_connection):
        mock_data = '''<?xml version="1.0"?>
                       <ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                         <Bucket>golang</Bucket>
                         <KeyMarker/>
                         <UploadIdMarker/>
                         <NextKeyMarker/>
                         <NextUploadIdMarker/>
                         <EncodingType/>
                         <MaxUploads>1000</MaxUploads>
                         <IsTruncated>false</IsTruncated>
                         <Prefix/>
                         <Delimiter/>
                       </ListMultipartUploadsResult>
                    '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET',
                         'https://localhost:9000/bucket/?max-uploads=1000&prefix=&uploads=',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data))
        client = Minio('localhost:9000')
        upload_iter = client._list_incomplete_uploads('bucket', '', True, False)
        uploads = []
        for upload in upload_iter:
            uploads.append(upload)
        eq_(0, len(uploads))

    @mock.patch('urllib3.PoolManager')
    def test_list_uploads_works(self, mock_connection):
        mock_data = '''<?xml version="1.0"?>
                       <ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                         <Bucket>golang</Bucket>
                         <KeyMarker/>
                         <UploadIdMarker/>
                         <NextKeyMarker>keymarker</NextKeyMarker>
                         <NextUploadIdMarker>uploadidmarker</NextUploadIdMarker>
                         <EncodingType/>
                         <MaxUploads>1000</MaxUploads>
                         <IsTruncated>false</IsTruncated>
                         <Upload>
                           <Key>go1.4.2</Key>
                           <UploadId>uploadid</UploadId>
                           <Initiator>
                             <ID/>
                             <DisplayName/>
                           </Initiator>
                           <Owner>
                             <ID/>
                             <DisplayName/>
                           </Owner>
                           <StorageClass/>
                           <Initiated>2015-05-30T14:43:35.349Z</Initiated>
                         </Upload>
                         <Upload>
                           <Key>go1.5.0</Key>
                           <UploadId>uploadid2</UploadId>
                           <Initiator>
                             <ID/>
                             <DisplayName/>
                           </Initiator>
                           <Owner>
                             <ID/>
                             <DisplayName/>
                           </Owner>
                           <StorageClass/>
                           <Initiated>2015-05-30T15:00:07.759Z</Initiated>
                         </Upload>
                         <Prefix/>
                         <Delimiter/>
                       </ListMultipartUploadsResult>
                    '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET',
                         'https://localhost:9000/bucket/?delimiter=%2F&max-uploads=1000&prefix=&uploads=',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         200, content=mock_data))

        client = Minio('localhost:9000')
        upload_iter = client._list_incomplete_uploads('bucket', '', False, False)
        uploads = []
        for upload in upload_iter:
            uploads.append(upload)
        eq_(2, len(uploads))

    @mock.patch('urllib3.PoolManager')
    def test_list_multipart_uploads_works(self, mock_connection):
        mock_data1 = '''<?xml version="1.0"?>
                        <ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                          <Bucket>golang</Bucket>
                          <KeyMarker/>
                          <UploadIdMarker/>
                          <NextKeyMarker>keymarker</NextKeyMarker>
                          <NextUploadIdMarker>uploadidmarker</NextUploadIdMarker>
                          <EncodingType/>
                          <MaxUploads>1000</MaxUploads>
                          <IsTruncated>true</IsTruncated>
                          <Upload>
                            <Key>go1.4.2</Key>
                            <UploadId>uploadid</UploadId>
                            <Initiator>
                              <ID/>
                              <DisplayName/>
                            </Initiator>
                            <Owner>
                              <ID/>
                              <DisplayName/>
                            </Owner>
                            <StorageClass/>
                            <Initiated>2015-05-30T14:43:35.349Z</Initiated>
                          </Upload>
                          <Upload>
                            <Key>go1.5.0</Key>
                            <UploadId>uploadid2</UploadId>
                            <Initiator>
                              <ID/>
                              <DisplayName/>
                            </Initiator>
                            <Owner>
                              <ID/>
                              <DisplayName/>
                            </Owner>
                            <StorageClass/>
                            <Initiated>2015-05-30T15:00:07.759Z</Initiated>
                          </Upload>
                          <Prefix/>
                          <Delimiter/>
                        </ListMultipartUploadsResult>
                     '''
        mock_data2 = '''<?xml version="1.0"?>
                        <ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                          <Bucket>golang</Bucket>
                          <KeyMarker/>
                          <UploadIdMarker/>
                          <NextKeyMarker/>
                          <NextUploadIdMarker/>
                          <EncodingType/>
                          <MaxUploads>1000</MaxUploads>
                          <IsTruncated>false</IsTruncated>
                          <Upload>
                            <Key>go1.4.2</Key>
                            <UploadId>uploadid</UploadId>
                            <Initiator>
                              <ID/>
                              <DisplayName/>
                            </Initiator>
                            <Owner>
                              <ID/>
                              <DisplayName/>
                            </Owner>
                            <StorageClass/>
                            <Initiated>2015-05-30T14:43:35.349Z</Initiated>
                          </Upload>
                          <Upload>
                            <Key>go1.5.0</Key>
                            <UploadId>uploadid2</UploadId>
                            <Initiator>
                              <ID/>
                              <DisplayName/>
                            </Initiator>
                            <Owner>
                              <ID/>
                              <DisplayName/>
                            </Owner>
                            <StorageClass/>
                            <Initiated>2015-05-30T15:00:07.759Z</Initiated>
                          </Upload>
                          <Prefix/>
                          <Delimiter/>
                        </ListMultipartUploadsResult>
                     '''
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET',
                         'https://localhost:9000/bucket/?max-uploads=1000&prefix=&uploads=',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data1))

        client = Minio('localhost:9000')
        upload_iter = client._list_incomplete_uploads('bucket', '', True, False)
        uploads = []
        for upload in upload_iter:
            mock_server.mock_add_request(MockResponse('GET',
                                                      'https://localhost:9000/bucket/?'
                                                      'key-marker=keymarker&'
                                                      'max-uploads=1000&prefix=&'
                                                      'upload-id-marker=uploadidmarker&uploads=',
                                                      {'User-Agent': _DEFAULT_USER_AGENT}, 200, content=mock_data2))
            uploads.append(upload)

        eq_(4, len(uploads))
