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
from .signer import sign_v4

__author__ = 'minio'

class ListObjectsIterator:
    def __init__(self, scheme, location, bucket, prefix, recursive):
        self.scheme = scheme
        self.location = location
        self.bucket = bucket
        self.prefix = prefix
        self.recursive = recursive
        self.results = []
        self.complete = False

    def __iter__(self):
        return self

    def next(self):
        if self.complete:
            raise StopIteration
        if len(self.results) == 0:
            self._fetch()
        if len(self.results) == 0:
            self.complete = True
            raise StopIteration
        return self.results.pop(0)

    def _fetch(self):
        query = {}
        if self.prefix is not None:
            query['prefix'] = self.prefix
        if not self.recursive:
            query['delim'] = '/'
        url = get_target_url(scheme, location, bucket=bucket,query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=client._access_key,
                          secret_key=client._secret_key)

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            self.client.parse_error(response)

        pass
