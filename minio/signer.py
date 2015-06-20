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

from urlparse import urlparse
from datetime import datetime

__author__ = 'fkautz'

empty_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def sign_v4(method, url, headers=None, access_key=None, secret_key=None, content_hash=empty_sha256):
    if access_key is None or secret_key is None:
        return

    if headers is None:
        headers = {}

    headers = headers[:]

    parsed_url = urlparse(url)

    headers['host'] = parsed_url.hostname
    headers['x-amz-date'] = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    headers['x-amz-content-sha256'] = content_hash

    canonical_request, signed_headers = generate_canonical_request(method, parsed_url, headers, content_hash)

    region = 'milkyway'

    dt = datetime.utcnow()

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('UTF-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()

    string_to_sign = generate_string_to_sign(dt, region, canonical_request_sha256)
    signing_key = generate_signing_key(dt, region, secret_key)
    signed_request = hmac.new(signing_key.encode('UTF-8'), string_to_sign.encode('UTF-8'), hashlib.sha256).hexdigest()

    authorization_header = generate_authorization_header(access_key, dt, region, signed_headers, signed_request)

    headers['authorization'] = authorization_header

    return headers


def generate_canonical_request(method, parsed_url, headers, content_hash):
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

    return '\n'.join(lines), signed_headers


def generate_string_to_sign(dt, region, request_hash):
    formatted_date_time = dt.strftime("%Y%m%dT000000Z")
    formatted_date = dt.strftime("%Y%m%d")

    scope = '/'.join([formatted_date, region, 's3', 'aws4_request'])

    return '\n'.join(['AWS4-HMAC-SHA256', formatted_date_time, scope, request_hash])


def generate_signing_key(dt, region, secret):
    formatted_date = dt.strftime("%Y%m%d")

    key1_string = 'AWS4' + secret
    key1 = key1_string.encode('UTF-8')
    key2 = hmac.new(key1, formatted_date.encode('UTF-8'), hashlib.sha256).digest()
    key3 = hmac.new(key2, region.encode('UTF-8'), hashlib.sha256).digest()
    key4 = hmac.new(key3, 's3'.encode('UTF-8'), hashlib.sha256).digest()

    return hmac.new(key4, 'aws4_request'.encode('UTF-8'), hashlib.sha256).hexdigest()


def generate_authorization_header(access_key, dt, region, signed_headers, signed_request):
    formatted_date = dt.strftime("%Y%m%d")
    signed_headers_string = ','.join(signed_headers)
    return "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + formatted_date + "/" + region + \
           "/s3/aws4_request,SignedHeaders=" + signed_headers_string + ",Signature=" + signed_request
