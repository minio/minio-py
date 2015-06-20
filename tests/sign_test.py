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

from nose.tools import eq_

from minio.signer import canonical_request

__author__ = 'fkautz'


class CanonicalRequest(TestCase):
    def test_simple_request(self):
        expected_request_array = ['PUT', '/hello', '', 'x-amz-date=dateString', '', 'x-amz-date',
                                  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']

        expected_request = '\n'.join(expected_request_array)
        actual_request = canonical_request('PUT', '/hello', {'X-Amz-Date': 'dateString'})
        eq_(expected_request, actual_request)
