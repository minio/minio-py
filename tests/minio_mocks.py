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

from nose.tools import eq_

__author__ = 'minio'


class MockResponse(object):
    def __init__(self, method, url, headers, status_code, return_headers=None, content=None):
        self.method = method
        self.url = url
        self.headers = headers
        self.status_code = status_code
        self.return_headers = return_headers
        self.content = content

    def mock_verify(self, method, url, headers):
        eq_(self.method, method)
        eq_(self.url, url)
        eq_(self.headers, headers)

    # noinspection PyUnusedLocal
    def iter_content(self, chunk_size=1, decode_unicode=False):
        if self.content is not None:
            return iter(bytearray(self.content, 'utf-8'))
        return iter([])


class MockConnection(object):
    def __init__(self):
        self.requests = []

    def mock_add_request(self, request):
        self.requests.append(request)

    def request(self, method, url, headers):
        return_request = self.requests.pop(0)
        return_request.mock_verify(method, url, headers)
        return return_request
