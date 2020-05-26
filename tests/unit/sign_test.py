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
from datetime import datetime
from unittest import TestCase

import pytz as pytz
from nose.tools import eq_, raises

from minio.compat import queryencode, quote, urlsplit
from minio.credentials import Credentials, Static, Value
from minio.error import InvalidArgumentError
from minio.fold_case_dict import FoldCaseDict
from minio.helpers import get_target_url
from minio.signer import (generate_authorization_header,
                          generate_canonical_request, generate_signing_key,
                          generate_string_to_sign, presign_v4, sign_v4)

empty_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
dt = datetime(2015, 6, 20, 1, 2, 3, 0, pytz.utc)


class CanonicalRequestTest(TestCase):
    def test_simple_request(self):
        url = urlsplit('http://localhost:9000/hello')
        expected_signed_headers = ['x-amz-content-sha256', 'x-amz-date']
        expected_request_array = ['PUT', '/hello', '',
                                  'x-amz-content-sha256:' +
                                  empty_hash, 'x-amz-date:dateString',
                                  '', ';'.join(expected_signed_headers),
                                  empty_hash]
        headers_to_sign = FoldCaseDict({'X-Amz-Date': 'dateString',
                                        'X-Amz-Content-Sha256': empty_hash})

        expected_request = '\n'.join(expected_request_array)
        actual_request = generate_canonical_request('PUT',
                                                    url,
                                                    headers_to_sign,
                                                    expected_signed_headers,
                                                    empty_hash)

        eq_(expected_request, actual_request)

    def test_request_with_query(self):
        url = urlsplit('http://localhost:9000/hello?c=d&e=f&a=b')
        expected_signed_headers = ['x-amz-content-sha256', 'x-amz-date']
        expected_request_array = ['PUT', '/hello', 'c=d&e=f&a=b',
                                  'x-amz-content-sha256:' + empty_hash,
                                  'x-amz-date:dateString',
                                  '', ';'.join(expected_signed_headers),
                                  empty_hash]

        expected_request = '\n'.join(expected_request_array)

        headers_to_sign = FoldCaseDict({'X-Amz-Date': 'dateString',
                                        'X-Amz-Content-Sha256': empty_hash})

        actual_request = generate_canonical_request('PUT',
                                                    url,
                                                    headers_to_sign,
                                                    expected_signed_headers,
                                                    empty_hash)

        eq_(expected_request, actual_request)


class StringToSignTest(TestCase):
    def test_signing_key(self):
        expected_signing_key_list = [
            'AWS4-HMAC-SHA256', '20150620T010203Z',
            '20150620/us-east-1/s3/aws4_request',
            'b93e86965c269a0dfef37a8bec231ef8acf8cdb101a64eb700a46c452c1ad233'
        ]

        actual_signing_key = generate_string_to_sign(
            dt, 'us-east-1', 'request_hash', 's3')
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

        actual_result = generate_signing_key(dt, 'region', 'S3CR3T')

        eq_(expected_result, actual_result)


class AuthorizationHeaderTest(TestCase):
    def test_generate_authentication_header(self):
        expected_authorization_header = (
            'AWS4-HMAC-SHA256 Credential='
            'public_key/20150620/region/s3/aws4_request, '
            'SignedHeaders=host;X-Amz-Content-Sha256;X-Amz-Date, '
            'Signature=signed_request'
        )
        actual_authorization_header = generate_authorization_header(
            'public_key', dt, 'region',
            ['host', 'X-Amz-Content-Sha256', 'X-Amz-Date'],
            'signed_request')
        eq_(expected_authorization_header, actual_authorization_header)


class PresignURLTest(TestCase):
    @raises(InvalidArgumentError)
    def test_presigned_no_access_key(self):
        credentials = Credentials(
            provider=Static(None, None),
        )
        presign_v4('GET', 'http://localhost:9000/hello', credentials, None)

    @raises(InvalidArgumentError)
    def test_presigned_invalid_expires(self):
        credentials = Credentials(
            provider=Static(None, None),
        )
        presign_v4('GET', 'http://localhost:9000/hello',
                   credentials, region=None, headers={}, expires=0)


class SignV4Test(TestCase):
    def test_signv4(self):
        # Construct target url.
        credentials = Credentials(
            provider=Static("minio", "minio123"),
        )
        url = get_target_url('http://localhost:9000',
                             bucket_name='testbucket',
                             object_name='~testobject',
                             bucket_region='us-east-1',
                             query={'partID': '1', 'uploadID': '~abcd'})
        hdrs = sign_v4('PUT', url, 'us-east-1',
                       credentials=credentials, request_datetime=dt)
        eq_(hdrs['Authorization'],
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
