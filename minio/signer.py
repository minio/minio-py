# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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

import collections
import hashlib
import hmac
import binascii

from datetime import datetime
from .error import InvalidArgumentError
from .compat import urlsplit, strtype, urlencode
from .helpers import get_region

def post_presign_signature(date, region, secret_key, policy_str):
    signing_key = generate_signing_key(date, region, secret_key)
    signature = hmac.new(signing_key, policy_str.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    return signature

def presign_v4(method, url, headers=None, access_key=None, secret_key=None, expires=None):
    if not access_key or not secret_key:
        raise InvalidArgumentError('invalid access/secret id')

    # verify only if 'None' not on expires with 0 value which should
    # be an InvalidArgument is handled later below
    if expires is None:
        expires = 604800

    if expires < 1 or expires > 604800:
        raise InvalidArgumentError('expires param valid values are between 1 secs to 604800 secs')

    if headers is None:
        headers = {}

    parsed_url = urlsplit(url)
    content_hash_hex = 'UNSIGNED-PAYLOAD'
    host = parsed_url.netloc
    headers['host'] = host
    date = datetime.utcnow()
    iso8601Date = date.strftime("%Y%m%dT%H%M%SZ")
    region = get_region(parsed_url.hostname)

    headers_to_sign = dict(headers)
    ignored_headers = ['Authorization', 'Content-Length', 'Content-Type',
                       'User-Agent']

    for ignored_header in ignored_headers:
        if ignored_header in headers_to_sign:
            del headers_to_sign[ignored_header]

    query = {}
    query['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
    query['X-Amz-Credential'] = generate_credential_string(access_key, date, region)
    query['X-Amz-Date'] = iso8601Date
    query['X-Amz-Expires'] = expires
    query['X-Amz-SignedHeaders']  = ';'.join(get_signed_headers(headers_to_sign))

    url_components = [parsed_url.geturl()]
    if query is not None:
        ordered_query = collections.OrderedDict(sorted(query.items()))
        query_components = []
        for component_key in ordered_query:
            single_component = [component_key]
            if ordered_query[component_key] is not None:
                single_component.append('=')
                single_component.append(
                    urlencode(str(ordered_query[component_key])).replace('/', '%2F'))
            query_components.append(''.join(single_component))

        query_string = '&'.join(query_components)
        if query_string:
            url_components.append('?')
            url_components.append(query_string)
    new_url = ''.join(url_components)
    new_parsed_url = urlsplit(new_url)
    canonical_request = generate_canonical_request(method,
                                                   new_parsed_url,
                                                   headers_to_sign,
                                                   content_hash_hex)

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('utf-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()

    string_to_sign = generate_string_to_sign(date, region,
                                             canonical_request_sha256)
    signing_key = generate_signing_key(date, region, secret_key)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    new_parsed_url = urlsplit(new_url + "&X-Amz-Signature="+signature)
    return new_parsed_url.geturl()

def get_signed_headers(headers):
    headers_to_sign = dict(headers)
    ignored_headers = ['Authorization', 'Content-Length', 'Content-Type',
                       'User-Agent']

    for ignored_header in ignored_headers:
        if ignored_header in headers_to_sign:
            del headers_to_sign[ignored_header]

    signed_headers = []
    for header in headers:
        signed_headers.append(header)
    signed_headers.sort()

    return signed_headers

def sign_v4(method, url, headers=None, access_key=None, secret_key=None,
            content_hash=None):
    if not access_key or not secret_key:
        return headers

    if headers is None:
        headers = {}

    parsed_url = urlsplit(url)
    content_hash_hex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    if content_hash is not None:
        content_hash_hex = binascii.hexlify(content_hash).decode('utf-8')

    host = parsed_url.netloc
    headers['host'] = host
    region = get_region(parsed_url.hostname)

    date = datetime.utcnow()
    headers['x-amz-date'] = date.strftime("%Y%m%dT%H%M%SZ")
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

    ignored_headers = ['Authorization', 'Content-Length', 'Content-Type',
                       'User-Agent']

    for ignored_header in ignored_headers:
        if ignored_header in headers_to_sign:
            del headers_to_sign[ignored_header]

    signed_headers = get_signed_headers(headers_to_sign)
    canonical_request = generate_canonical_request(method,
                                                    parsed_url,
                                                    headers_to_sign,
                                                    content_hash_hex)

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('utf-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()

    string_to_sign = generate_string_to_sign(date, region,
                                             canonical_request_sha256)
    signing_key = generate_signing_key(date, region, secret_key)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    authorization_header = generate_authorization_header(access_key, date, region,
                                                         signed_headers,
                                                         signature)

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
        if isinstance(value, strtype):
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

    return '\n'.join(lines)


def generate_string_to_sign(date, region, request_hash):
    formatted_date_time = date.strftime("%Y%m%dT%H%M%SZ")

    return '\n'.join(['AWS4-HMAC-SHA256',
                      formatted_date_time,
                      generate_scope_string(date, region),
                      request_hash])


def generate_signing_key(date, region, secret):
    formatted_date = date.strftime("%Y%m%d")

    key1_string = 'AWS4' + secret
    key1 = key1_string.encode('utf-8')
    key2 = hmac.new(key1, formatted_date.encode('utf-8'),
                    hashlib.sha256).digest()
    key3 = hmac.new(key2, region.encode('utf-8'), hashlib.sha256).digest()
    key4 = hmac.new(key3, 's3'.encode('utf-8'), hashlib.sha256).digest()

    return hmac.new(key4, 'aws4_request'.encode('utf-8'),
                    hashlib.sha256).digest()

def generate_scope_string(date, region):
    formatted_date = date.strftime("%Y%m%d")
    scope = '/'.join([formatted_date,
                      region,
                      's3',
                      'aws4_request'])
    return scope

def generate_credential_string(access_key, date, region):
    return access_key + '/' +  generate_scope_string(date, region)

def generate_authorization_header(access_key, date, region, signed_headers,
                                  signature):
    signed_headers_string = ';'.join(signed_headers)
    credential = generate_credential_string(access_key, date, region)
    auth_header = "AWS4-HMAC-SHA256 Credential=" + credential + ", SignedHeaders=" + \
                  signed_headers_string + ", Signature=" + signature
    return auth_header
