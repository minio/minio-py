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
from .parsers import parse_list_objects
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

    def __iter__(self):
        return self

    def next(self):
        if self._complete:
            raise StopIteration
        if len(self._results) == 0:
            self._results = self._fetch()
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        return self._results.pop(0)

    def _fetch(self):
        query = {}
        if self._prefix is not None:
            query['prefix'] = self._prefix
        if not self._recursive:
            query['delim'] = '/'

        url = get_target_url(self._scheme, self._location, bucket=self._bucket,query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            self.client.parse_error(response)
        return parse_list_objects(response.content)
        # parse
