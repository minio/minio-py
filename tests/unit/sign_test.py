# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import hmac
from datetime import datetime, timezone
from unittest import TestCase
from urllib.parse import urlsplit, urlunsplit

from nose.tools import eq_

from minio import Minio
from minio.credentials import Credentials
from minio.helpers import queryencode, quote, sha256_hash
from minio.signer import (_get_authorization, _get_canonical_request_hash,
                          _get_scope, _get_signing_key, _get_string_to_sign,
                          presign_v4, sign_v4_s3)

empty_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
dt = datetime(2015, 6, 20, 1, 2, 3, 0, timezone.utc)


class CanonicalRequestTest(TestCase):
    def test_simple_request(self):
        url = urlsplit('http://localhost:9000/hello')
        expected_signed_headers = ['x-amz-content-sha256', 'x-amz-date']
        expected_request_array = ['PUT', '/hello', '',
                                  'x-amz-content-sha256:' +
                                  empty_hash, 'x-amz-date:dateString',
                                  '', ';'.join(expected_signed_headers),
                                  empty_hash]
        headers_to_sign = {'x-amz-date': 'dateString',
                           'x-amz-content-sha256': empty_hash}

        expected_request = sha256_hash('\n'.join(expected_request_array))
        actual_request = _get_canonical_request_hash(
            "PUT", url, headers_to_sign, empty_hash,
        )
        eq_(expected_request, actual_request[0])

    def test_request_with_query(self):
        url = urlsplit('http://localhost:9000/hello?c=d&e=f&a=b')
        expected_signed_headers = ['x-amz-content-sha256', 'x-amz-date']
        expected_request_array = ['PUT', '/hello', 'a=b&c=d&e=f',
                                  'x-amz-content-sha256:' + empty_hash,
                                  'x-amz-date:dateString',
                                  '', ';'.join(expected_signed_headers),
                                  empty_hash]

        expected_request = sha256_hash('\n'.join(expected_request_array))

        headers_to_sign = {'x-amz-date': 'dateString',
                           'x-amz-content-sha256': empty_hash}
        actual_request = _get_canonical_request_hash(
            "PUT", url, headers_to_sign, empty_hash,
        )
        eq_(expected_request, actual_request[0])


class StringToSignTest(TestCase):
    def test_signing_key(self):
        expected_signing_key_list = [
            'AWS4-HMAC-SHA256', '20150620T010203Z',
            '20150620/us-east-1/s3/aws4_request',
            'b93e86965c269a0dfef37a8bec231ef8acf8cdb101a64eb700a46c452c1ad233'
        ]

        actual_signing_key = _get_string_to_sign(
            dt, _get_scope(dt, 'us-east-1', "s3"),
            'b93e86965c269a0dfef37a8bec231ef8acf8cdb101a64eb700a46c452c1ad233')
        eq_('\n'.join(expected_signing_key_list), actual_signing_key)


class SigningKeyTest(TestCase):
    def test_generate_signing_key(self):
        key1_string = 'AWS4' + 'S3CR3T'
        key1 = key1_string.encode('utf-8')
        key2 = hmac.new(key1, '20150620'.encode(
            'utf-8'), hashlib.sha256).digest()
        key3 = hmac.new(key2, 'region'.encode(
            'utf-8'), hashlib.sha256).digest()
        key4 = hmac.new(key3, 's3'.encode('utf-8'), hashlib.sha256).digest()
        expected_result = hmac.new(key4, 'aws4_request'.encode(
            'utf-8'), hashlib.sha256).digest()

        actual_result = _get_signing_key('S3CR3T', dt, 'region', "s3")
        eq_(expected_result, actual_result)


class AuthorizationHeaderTest(TestCase):
    def test_generate_authentication_header(self):
        expected_authorization_header = (
            'AWS4-HMAC-SHA256 Credential='
            'public_key/20150620/region/s3/aws4_request, '
            'SignedHeaders=host;X-Amz-Content-Sha256;X-Amz-Date, '
            'Signature=signed_request'
        )
        actual_authorization_header = _get_authorization(
            'public_key', _get_scope(dt, 'region', "s3"),
            'host;X-Amz-Content-Sha256;X-Amz-Date', 'signed_request')
        eq_(expected_authorization_header, actual_authorization_header)


class PresignURLTest(TestCase):
    def test_presigned_versioned_id(self):
        credentials = Credentials("minio", "minio123")
        url = presign_v4('GET', urlsplit('http://localhost:9000/bucket-name/objectName?versionId=uuid'),
                         'us-east-1', credentials, dt, 604800)

        eq_(urlunsplit(url), 'http://localhost:9000/bucket-name/objectName?versionId=uuid&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=minio%2F20150620%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20150620T010203Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=3ce13e2ca929fafa20581a05730e4e9435f2a5e20ec7c5a082d175692fb0a663')


class SignV4Test(TestCase):
    def test_signv4(self):
        client = Minio("localhost:9000", access_key="minio",
                       secret_key="minio123", secure=False)
        creds = client._provider.retrieve()
        headers = {
            'Host': 'localhost:9000',
            'x-amz-content-sha256':
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'x-amz-date': '20150620T010203Z',
        }
        url = client._base_url.build(
            "PUT",
            "us-east-1",
            bucket_name="testbucket",
            object_name="~testobject",
            query_params={"partID": "1", "uploadID": "~abcd"},
        )
        headers = sign_v4_s3(
            "PUT",
            url,
            "us-east-1",
            headers,
            creds,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            dt,
        )
        eq_(headers['Authorization'],
            'AWS4-HMAC-SHA256 Credential='
            'minio/20150620/us-east-1/s3/aws4_request, '
            'SignedHeaders=host;x-amz-content-sha256;x-amz-date, '
            'Signature='
            'a2f4546f647981732bd90dfa5a7599c44dca92f44bea48ecc7565df06032c25b')


class UnicodeEncodeTest(TestCase):
    def test_unicode_quote(self):
        eq_(quote('/test/123/汉字'), '/test/123/%E6%B1%89%E5%AD%97')

    def test_unicode_queryencode(self):
        eq_(queryencode('/test/123/汉字'), '%2Ftest%2F123%2F%E6%B1%89%E5%AD%97')

    def test_unicode_quote_u(self):
        eq_(quote(u'/test/123/汉字'), '/test/123/%E6%B1%89%E5%AD%97')

    def test_unicode_queryencode_u(self):
        eq_(queryencode(u'/test/123/汉字'), '%2Ftest%2F123%2F%E6%B1%89%E5%AD%97')

    def test_unicode_quote_b(self):
        eq_(quote(b'/test/123/\xe6\xb1\x89\xe5\xad\x97'),
            '/test/123/%E6%B1%89%E5%AD%97')

    def test_unicode_queryencode_b(self):
        eq_(queryencode(b'/test/123/\xe6\xb1\x89\xe5\xad\x97'),
            '%2Ftest%2F123%2F%E6%B1%89%E5%AD%97')
