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
import hashlib
import hmac
from unittest import TestCase
from datetime import datetime

from nose.tools import eq_
import pytz as pytz

from .compat import compat_urllib_parse
from minio.signer import generate_canonical_request, generate_string_to_sign, generate_signing_key, \
    generate_authorization_header

__author__ = 'minio'

empty_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
dt = datetime(2015, 6, 20, 1, 2, 3, 0, pytz.utc)

class CanonicalRequestTest(TestCase):
    def test_simple_request(self):
        url = compat_urllib_parse('http://localhost:9000/hello')
        expected_signed_headers = ['x-amz-content-sha256', 'x-amz-date']
        expected_request_array = ['PUT', '/hello', '',
                                  'x-amz-content-sha256:' +
                                  empty_hash, 'x-amz-date:dateString',
                                  '', ';'.join(expected_signed_headers),
                                  empty_hash]

        expected_request = '\n'.join(expected_request_array)

        actual_request, actual_signed_headers = generate_canonical_request('PUT',
                                                                           url,
                                                                           {'X-Amz-Date': 'dateString',
                                                                            '   x-Amz-Content-sha256\t': "\t" +
                                                                                                         empty_hash +
                                                                                                         " "},
                                                                           empty_hash)

        eq_(expected_request, actual_request)
        eq_(expected_signed_headers, actual_signed_headers)

    def test_request_with_query(self):
        url = compat_urllib_parse('http://localhost:9000/hello?c=d&e=f&a=b')
        expected_signed_headers = ['x-amz-content-sha256', 'x-amz-date']
        expected_request_array = ['PUT', '/hello', 'a=b&c=d&e=f',
                                  'x-amz-content-sha256:' + empty_hash,
                                  'x-amz-date:dateString',
                                  '', ';'.join(expected_signed_headers),
                                  empty_hash]

        expected_request = '\n'.join(expected_request_array)

        actual_request, actual_signed_headers = generate_canonical_request('PUT',
                                                                           url,
                                                                           {'X-Amz-Date': 'dateString',
                                                                            '   x-Amz-Content-sha256\t': "\t" +
                                                                                                         empty_hash +
                                                                                                         " "},
                                                                           empty_hash)

        eq_(expected_request, actual_request)


class StringToSignTest(TestCase):
    def test_signing_key(self):
        expected_signing_key_list = ["AWS4-HMAC-SHA256", "20150620T010203Z",
                                     "20150620/milkyway/s3/aws4_request",
                                     'request_hash']

        actual_signing_key = generate_string_to_sign(dt, "milkyway", 'request_hash')
        eq_('\n'.join(expected_signing_key_list), actual_signing_key)


class SigningKeyTest(TestCase):
    def test_generate_signing_key(self):
        key1_string = 'AWS4' + 'S3CR3T'
        key1 = key1_string.encode('utf-8')
        key2 = hmac.new(key1, '20150620'.encode('utf-8'), hashlib.sha256).digest()
        key3 = hmac.new(key2, 'region'.encode('utf-8'), hashlib.sha256).digest()
        key4 = hmac.new(key3, 's3'.encode('utf-8'), hashlib.sha256).digest()
        expected_result = hmac.new(key4, 'aws4_request'.encode('utf-8'), hashlib.sha256).digest()

        actual_result = generate_signing_key(dt, 'region', 'S3CR3T')

        eq_(expected_result, actual_result)


class AuthorizationHeaderTest(TestCase):
    def test_generate_authentication_header(self):
        expected_authorization_header = "AWS4-HMAC-SHA256 Credential=public_key/20150620/region/s3/aws4_request, " \
                                        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=signed_request"
        actual_authorization_header = generate_authorization_header('public_key', dt, 'region',
                                                                    ['host', 'x-amz-content-sha256', 'x-amz-date'],
                                                                    'signed_request')
        eq_(expected_authorization_header, actual_authorization_header)
