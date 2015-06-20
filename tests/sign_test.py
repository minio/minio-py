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
from urlparse import urlparse

from nose.tools import eq_

from minio.signer import canonical_request

__author__ = 'fkautz'

empty_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


class CanonicalRequest(TestCase):
    def test_simple_request(self):
        url = urlparse('http://localhost:9000/hello')
        expected_request_array = ['PUT', '/hello', '', 'x-amz-content-sha256=' + empty_hash, 'x-amz-date=dateString',
                                  '', 'x-amz-content-sha256;x-amz-date',
                                  empty_hash]

        expected_request = '\n'.join(expected_request_array)

        actual_request = canonical_request('PUT', url, {'X-Amz-Date': 'dateString',
                                                        '   x-Amz-Content-sha256\t': "\t" + empty_hash + " "},
                                           empty_hash)

        eq_(expected_request, actual_request)

    def test_request_with_query(self):
        url = urlparse('http://localhost:9000/hello?c=d&e=f&a=b')
        expected_request_array = ['PUT', '/hello', 'a=b&c=d&e=f', 'x-amz-content-sha256=' + empty_hash,
                                  'x-amz-date=dateString',
                                  '', 'x-amz-content-sha256;x-amz-date',
                                  empty_hash]

        expected_request = '\n'.join(expected_request_array)

        actual_request = canonical_request('PUT', url, {'X-Amz-Date': 'dateString',
                                                        '   x-Amz-Content-sha256\t': "\t" + empty_hash + " "},
                                           empty_hash)

        eq_(expected_request, actual_request)
