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
from nose.tools import raises, eq_

from minio import minio
from minio.acl import Acl
from tests.minio_mocks import MockResponse

__author__ = 'minio'


class GetBucketAclTest(TestCase):
    @raises(TypeError)
    def test_bucket_is_string(self):
        client = minio.Minio('http://localhost:9000')
        client.get_bucket_acl(1234)

    @raises(ValueError)
    def test_bucket_is_not_empty_string(self):
        client = minio.Minio('http://localhost:9000')
        client.get_bucket_acl('  \t \n  ')

    @mock.patch('requests.get')
    def test_public_read_write_response(self, mock_request):
        content = '''
                  <AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01">
                    <Owner>
                      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                      <DisplayName>CustomersName@amazon.com</DisplayName>
                    </Owner>
                    <AccessControlList>
                      <Grant>
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                          <DisplayName>CustomersName@amazon.com</DisplayName>
                          <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
                        </Grantee>
                        <Permission>WRITE</Permission>
                      </Grant>
                      <Grant>
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                          <DisplayName>CustomersName@amazon.com</DisplayName>
                          <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
                        </Grantee>
                        <Permission>READ</Permission>
                      </Grant>
                      <Grant>
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                          <DisplayName>CustomersName@amazon.com</DisplayName>
                        </Grantee>
                        <Permission>FULL_CONTROL</Permission>
                      </Grant>
                    </AccessControlList>
                  </AccessControlPolicy>
                  '''
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/hello?acl', {}, 200, content=content)
        client = minio.Minio('http://localhost:9000')
        acl = client.get_bucket_acl('hello')
        eq_(Acl.public_read_write(), acl)

    @mock.patch('requests.get')
    def test_public_read(self, mock_request):
        content = '''
                  <AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01"> \
                    <Owner> \
                      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID> \
                      <DisplayName>CustomersName@amazon.com</DisplayName> \
                    </Owner> \
                    <AccessControlList> \
                      <Grant> \
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"> \
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID> \
                          <DisplayName>CustomersName@amazon.com</DisplayName> \
                          <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI> \
                        </Grantee> \
                        <Permission>READ</Permission> \
                      </Grant> \
                      <Grant> \
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"> \
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID> \
                          <DisplayName>CustomersName@amazon.com</DisplayName> \
                        </Grantee> \
                        <Permission>FULL_CONTROL</Permission> \
                      </Grant> \
                    </AccessControlList> \
                  </AccessControlPolicy>
                  '''
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/hello?acl', {}, 200, content=content)
        client = minio.Minio('http://localhost:9000')
        acl = client.get_bucket_acl('hello')
        eq_(Acl.public_read(), acl)

    @mock.patch('requests.get')
    def test_authenticated_users(self, mock_request):
        content = '''
                  <AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01">
                    <Owner>
                      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                      <DisplayName>CustomersName@amazon.com</DisplayName>
                    </Owner>
                    <AccessControlList>
                      <Grant>
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                          <DisplayName>CustomersName@amazon.com</DisplayName>
                          <URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI>
                        </Grantee>
                        <Permission>READ</Permission>
                      </Grant>
                      <Grant>
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                          <DisplayName>CustomersName@amazon.com</DisplayName>
                        </Grantee>
                        <Permission>FULL_CONTROL</Permission>
                      </Grant>
                    </AccessControlList>
                  </AccessControlPolicy>
                  '''
        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/hello?acl', {}, 200, content=content)
        client = minio.Minio('http://localhost:9000')
        acl = client.get_bucket_acl('hello')
        eq_(Acl.authenticated(), acl)

    @mock.patch('requests.get')
    def test_private(self, mock_request):
        content = '''
                  <AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01">
                    <Owner>
                      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                      <DisplayName>CustomersName@amazon.com</DisplayName>
                    </Owner>
                    <AccessControlList>
                      <Grant>
                        <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                          <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
                          <DisplayName>CustomersName@amazon.com</DisplayName>
                        </Grantee>
                        <Permission>FULL_CONTROL</Permission>
                      </Grant>
                    </AccessControlList>
                  </AccessControlPolicy>
                  '''

        mock_request.return_value = MockResponse('GET', 'http://localhost:9000/hello?acl', {}, 200, content=content)
        client = minio.Minio('http://localhost:9000')
        acl = client.get_bucket_acl('hello')
        eq_(Acl.private(), acl)
