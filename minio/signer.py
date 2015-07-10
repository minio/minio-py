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
from datetime import datetime
import binascii

from .compat import compat_urllib_parse, compat_str_type
from .region import get_region

__author__ = 'minio'

empty_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def sign_v4(method, url, headers=None, access_key=None, secret_key=None, content_hash=None):
    if access_key is None or secret_key is None:
        return headers

    if headers is None:
        headers = {}

    parsed_url = compat_urllib_parse(url)

    content_hash_hex = empty_sha256
    if content_hash is not None:
        content_hash_hex = binascii.hexlify(content_hash).decode('utf-8')

    host = parsed_url.hostname
    if parsed_url.port is not None:
        if parsed_url.scheme == 'http' and parsed_url.port != 80:
            host = host + ":" + str(parsed_url.port)
        if parsed_url.scheme == 'https' and parsed_url.port != 443:
            host = host + ":" + str(parsed_url.port)

    headers['host'] = host
    headers['x-amz-date'] = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    headers['x-amz-content-sha256'] = content_hash_hex

    headers_to_sign = dict(headers)

    # Excerpts from @lsegal - https://github.com/aws/aws-sdk-js/issues/659#issuecomment-120477258
    #
    #  User-Agent:
    #
    #      This is ignored from signing because signing this causes problems with generating pre-signed URLs
    #      (that are executed by other agents) or when customers pass requests through proxies, which may
    #      modify the user-agent.
    #
    #  Content-Length:
    #
    #      This is ignored from signing because generating a pre-signed URL should not provide a content-length
    #      constraint, specifically when vending a S3 pre-signed PUT URL. The corollary to this is that when
    #      sending regular requests (non-pre-signed), the signature contains a checksum of the body, which
    #      implicitly validates the payload length (since changing the number of bytes would change the checksum)
    #      and therefore this header is not valuable in the signature.
    #
    #  Content-Type:
    #
    #      Signing this header causes quite a number of problems in browser environments, where browsers
    #      like to modify and normalize the content-type header in different ways. There is more information
    #      on this in https://github.com/aws/aws-sdk-js/issues/244. Avoiding this field simplifies logic
    #      and reduces the possibility of future bugs
    #
    #  Authorization:
    #
    #      Is skipped for obvious reasons

    ignored_headers = ['Authorization', 'Content-Length', 'Content-Type', 'User-Agent']

    for ignored_header in ignored_headers:
        if ignored_header in headers_to_sign:
            del headers_to_sign[ignored_header]

    canonical_request, signed_headers = generate_canonical_request(method, parsed_url, headers_to_sign,
                                                                   content_hash_hex)

    region = get_region(parsed_url.hostname)

    dt = datetime.utcnow()

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('utf-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()

    string_to_sign = generate_string_to_sign(dt, region, canonical_request_sha256)
    signing_key = generate_signing_key(dt, region, secret_key)
    signed_request = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = generate_authorization_header(access_key, dt, region, signed_headers, signed_request)

    headers['authorization'] = authorization_header

    return headers


def generate_canonical_request(method, parsed_url, headers, content_hash_hex):
    content_hash_hex = str(content_hash_hex)
    lines = [method, parsed_url.path]

    split_query = parsed_url.query.split('&')
    split_query.sort()
    for i in range(0, len(split_query)):
        if len(split_query[i]) > 0 and '=' not in split_query[i]:
            split_query[i] += '='

    query = '&'.join(split_query)
    lines.append(query)

    signed_headers = []
    header_lines = []
    for header in headers:
        value = headers[header]
        if isinstance(value, compat_str_type):
            value = value.strip()
        header = header.lower().strip()
        signed_headers.append(header)
        header_lines.append(header.lower().strip() + ':' + str(value))
    signed_headers.sort()
    header_lines.sort()
    lines = lines + header_lines

    lines.append('')

    lines.append(';'.join(signed_headers))
    lines.append(str(content_hash_hex))

    return '\n'.join(lines), signed_headers


def generate_string_to_sign(dt, region, request_hash):
    formatted_date_time = dt.strftime("%Y%m%dT%H%M%SZ")
    formatted_date = dt.strftime("%Y%m%d")

    scope = '/'.join([formatted_date, region, 's3', 'aws4_request'])

    return '\n'.join(['AWS4-HMAC-SHA256', formatted_date_time, scope, request_hash])


def generate_signing_key(dt, region, secret):
    formatted_date = dt.strftime("%Y%m%d")

    key1_string = 'AWS4' + secret
    key1 = key1_string.encode('utf-8')
    key2 = hmac.new(key1, formatted_date.encode('utf-8'), hashlib.sha256).digest()
    key3 = hmac.new(key2, region.encode('utf-8'), hashlib.sha256).digest()
    key4 = hmac.new(key3, 's3'.encode('utf-8'), hashlib.sha256).digest()

    return hmac.new(key4, 'aws4_request'.encode('utf-8'), hashlib.sha256).digest()


def generate_authorization_header(access_key, dt, region, signed_headers, signed_request):
    formatted_date = dt.strftime("%Y%m%d")
    signed_headers_string = ';'.join(signed_headers)
    return "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + formatted_date + "/" + region + \
           "/s3/aws4_request,SignedHeaders=" + signed_headers_string + ",Signature=" + signed_request
