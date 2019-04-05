# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015,2016 MinIO, Inc.
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

from minio.compat import _is_py3
from minio.fold_case_dict import FoldCaseDict

if _is_py3:
    import http.client as httplib
else:
    import httplib

from nose.tools import eq_

class MockResponse(object):
    def __init__(self, method, url, headers, status_code, response_headers=None,
                 content=None):
        self.method = method
        self.url = url
        self.request_headers = FoldCaseDict()
        for header in headers:
            self.request_headers[header] = headers[header]
        self.status = status_code
        self.headers = response_headers
        self.data = content
        if content is None:
            self.reason = httplib.responses[status_code]

    # noinspection PyUnusedLocal
    def read(self, amt=1024):
        return self.data

    def mock_verify(self, method, url, headers):
        eq_(self.method, method)
        eq_(self.url, url)
        for header in headers:
            eq_(self.request_headers[header], headers[header])

    # noinspection PyUnusedLocal
    def stream(self, chunk_size=1, decode_unicode=False):
        if self.data is not None:
            return iter(bytearray(self.data, 'utf-8'))
        return iter([])

    # dummy release connection call.
    def release_conn(self):
        return

class MockConnection(object):
    def __init__(self):
        self.requests = []

    def mock_add_request(self, request):
        self.requests.append(request)

    # noinspection PyUnusedLocal
    def request(self, method, url, headers, redirect=False):
        return_request = self.requests.pop(0)
        return_request.mock_verify(method, url, headers)
        return return_request

    # noinspection PyRedeclaration,PyUnusedLocal,PyUnusedLocal
    def urlopen(self, method, url, headers, preload_content=False, body=None,
                redirect=False):
        return self.request(method, url, headers)
