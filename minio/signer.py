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

from urlparse import urlparse

__author__ = 'fkautz'

empty_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def sign_v4(method, url, headers=None, access_key=None, secret_key=None, content_hash=empty_sha256):
    if access_key is None or secret_key is None:
        return

    canonical_request(method, url, headers)
    if headers is None:
        headers = {}

    parsed_url = urlparse(url)

    headers['host'] = parsed_url.hostname
    headers['x-amz-date'] = 'amzdate'
    headers['x-amz-content-sha256'] = content_hash
    pass


def canonical_request(method, parsed_url, headers, content_hash):
    lines = [method, parsed_url.path]

    split_query = parsed_url.query.split('&')
    split_query.sort()
    query = '&'.join(split_query)
    lines.append(query)

    signed_headers = []
    header_lines = []
    for header in headers:
        signed_headers.append(header.lower().strip())
        header_lines.append(header.lower().strip() + '=' + headers[header].strip())
    signed_headers.sort()
    header_lines.sort()
    lines = lines + header_lines

    lines.append('')

    lines.append(';'.join(signed_headers))
    lines.append(content_hash)

    return '\n'.join(lines)
