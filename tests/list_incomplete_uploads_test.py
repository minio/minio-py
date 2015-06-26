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
from minio.generators import ListIncompleteUploads
from .minio_mocks import MockResponse

__author__ = 'minio'


class ListIncompleteUploadsTest(TestCase):
    @mock.patch('requests.get')
    def test_empty_list_uploads_test(self, mock_request):
        mock_data = '''<?xml version="1.0"?>
<ListMultipartUploadsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
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
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data)
        upload_iter = ListIncompleteUploads('http', 'localhost:9000', 'bucket')
        uploads = []
        for upload in upload_iter:
            uploads.append(upload)
        eq_(0, len(uploads))

    @mock.patch('requests.get')
    def test_list_uploads_works(self, mock_request):
        mock_data = '''<?xml version="1.0"?>
<ListMultipartUploadsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
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
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data)
        upload_iter = ListIncompleteUploads('http', 'localhost:9000', 'bucket')
        uploads = []
        for upload in upload_iter:
            uploads.append(upload)
        eq_(2, len(uploads))

    @mock.patch('requests.get')
    def test_list_objects_works(self, mock_request):
        mock_data1 = '''<?xml version="1.0"?>
<ListMultipartUploadsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
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
<ListMultipartUploadsResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
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
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data1)
        upload_iter = ListIncompleteUploads('http', 'localhost:9000', 'bucket')
        uploads = []
        for upload in upload_iter:
            mock_request.return_value = MockResponse('GET', 'http://localhost:9000/bucket', {}, 200, content=mock_data2)
            uploads.append(upload)

        eq_(4, len(uploads))
