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
import requests

from .helpers import get_target_url
from .parsers import parse_list_objects, parse_error, parse_incomplete_uploads
from .signer import sign_v4

__author__ = 'minio'


class ListObjectsIterator:
    def __init__(self, scheme, location, bucket, prefix, recursive, access_key, secret_key):
        self._scheme = scheme
        self._location = location
        self._bucket = bucket
        self._prefix = prefix
        self._recursive = recursive
        self._results = []
        self._complete = False
        self._access_key = access_key
        self._secret_key = secret_key
        self._is_truncated = True
        self._marker = None

    def __iter__(self):
        return self

    def next(self):
        # if complete, end iteration
        if self._complete:
            raise StopIteration
        # if not truncated and we've emitted everything, end iteration
        if len(self._results) == 0 and self._is_truncated is False:
            self._complete = True
            raise StopIteration
        # perform another fetch
        if len(self._results) == 0:
            self._results, self._is_truncated, self._marker = self._fetch()
        # if fetch results in no elements, end iteration
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        # return result
        return self._results.pop(0)

    def _fetch(self):
        query = {}
        if self._prefix is not None:
            query['prefix'] = self._prefix
        if not self._recursive:
            query['delim'] = '/'
        if self._marker is not None:
            query['marker'] = self._marker

        url = get_target_url(self._scheme, self._location, bucket=self._bucket, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)
        return parse_list_objects(response.content, bucket=self._bucket)


class ListIncompleteUploads:
    def __init__(self, scheme, location, bucket, prefix=None, access_key=None, secret_key=None):
        # from user
        self._scheme = scheme
        self._location = location
        self._bucket = bucket
        self._prefix = prefix
        self._access_key = access_key
        self._secret_key = secret_key

        # internal variables
        self._results = []
        self._complete = False
        self._is_truncated = True
        self._key_marker = None
        self._upload_id_marker = None

    def __iter__(self):
        return self

    def next(self):
        # if complete, end iteration
        if self._complete:
            raise StopIteration
        # if not truncated and we've emitted everything, end iteration
        if len(self._results) == 0 and self._is_truncated is False:
            self._complete = True
            raise StopIteration
        # perform another fetch
        if len(self._results) == 0:
            self._results, self._is_truncated, self._key_marker = self._fetch()
        # if fetch results in no elements, end iteration
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        # return result
        return self._results.pop(0)

    def _fetch(self):
        query = {}
        if self._prefix is not None:
            query['prefix'] = self._prefix
        if self._key_marker is not None:
            query['key-marker'] = self._key_marker
        if self._upload_id_marker is not None:
            query['upload-id-marker'] = self._upload_id_marker

        url = get_target_url(self._scheme, self._location, bucket=self._bucket, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)
        return parse_incomplete_uploads(response.content, bucket=self._bucket)
