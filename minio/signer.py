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


"""
minio.signer
~~~~~~~~~~~~~~~

This module implements all helpers for AWS Signature version '4' support.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import collections
import hashlib
import hmac

from datetime import datetime
from .error import InvalidArgumentError
from .compat import urlsplit, urlencode
from .helpers import (ignore_headers, get_sha256_hexdigest)

# Signature version '4' algorithm.
_SIGN_V4_ALGORITHM = 'AWS4-HMAC-SHA256'

# Hardcoded S3 header value for X-Amz-Content-Sha256
_UNSIGNED_PAYLOAD = u'UNSIGNED-PAYLOAD'

def post_presign_signature(date, region, secret_key, policy_str):
    """
    Calculates signature version '4' for POST policy string.

    :param date: datetime formatted date.
    :param region: region of the bucket for the policy.
    :param secret_key: Amazon S3 secret access key.
    :param policy_str: policy string.
    :return: hexlified sha256 signature digest.
    """
    signing_key = generate_signing_key(date, region, secret_key)
    signature = hmac.new(signing_key, policy_str.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    return signature


def presign_v4(method, url, access_key, secret_key, region=None,
               headers=None, expires=None, response_headers=None):
    """
    Calculates signature version '4' for regular presigned URLs.

    :param method: Method to be presigned examples 'PUT', 'GET'.
    :param url: URL to be presigned.
    :param access_key: Access key id for your AWS s3 account.
    :param secret_key: Secrect access key for your AWS s3 account.
    :param region: region of the bucket, it is optional.
    :param headers: any additional HTTP request headers to
       be presigned, it is optional.
    :param expires: final expiration of the generated URL. Maximum is 7days.
    """

    # Validate input arguments.
    if not access_key or not secret_key:
        raise InvalidArgumentError('Invalid access_key and secret_key.')

    if region is None:
        region = 'us-east-1'

    if headers is None:
        headers = {}

    if expires is None:
        expires = 604800

    parsed_url = urlsplit(url)
    content_hash_hex = _UNSIGNED_PAYLOAD
    host = parsed_url.netloc
    headers['Host'] = host
    date = datetime.utcnow()
    iso8601Date = date.strftime("%Y%m%dT%H%M%SZ")

    headers_to_sign = dict(headers)

    if response_headers is not None:
        headers_to_sign.update(response_headers)

    # Remove amazon recommended headers.
    headers_to_sign = ignore_headers(headers)

    # Construct queries.
    query = {}
    query['X-Amz-Algorithm'] = _SIGN_V4_ALGORITHM
    query['X-Amz-Credential'] = generate_credential_string(access_key,
                                                           date, region)
    query['X-Amz-Date'] = iso8601Date
    query['X-Amz-Expires'] = expires
    signed_headers = get_signed_headers(headers_to_sign)
    query['X-Amz-SignedHeaders'] = ';'.join(signed_headers)

    if response_headers is not None:
        query.update(response_headers)

    # URL components.
    url_components = [parsed_url.geturl()]
    if query is not None:
        ordered_query = collections.OrderedDict(sorted(query.items()))
        query_components = []
        for component_key in ordered_query:
            single_component = [component_key]
            if ordered_query[component_key] is not None:
                single_component.append('=')
                single_component.append(
                    urlencode(
                        str(ordered_query[component_key])
                    ).replace('/',
                              '%2F'))
            query_components.append(''.join(single_component))

        query_string = '&'.join(query_components)
        if query_string:
            url_components.append('?')
            url_components.append(query_string)
    new_url = ''.join(url_components)
    # new url constructor block ends.
    new_parsed_url = urlsplit(new_url)

    canonical_request = generate_canonical_request(method,
                                                   new_parsed_url,
                                                   headers_to_sign,
                                                   content_hash_hex)
    string_to_sign = generate_string_to_sign(date, region,
                                             canonical_request)
    signing_key = generate_signing_key(date, region, secret_key)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()
    new_parsed_url = urlsplit(new_url + "&X-Amz-Signature="+signature)
    return new_parsed_url.geturl()



def get_signed_headers(headers):
    """
    Get signed headers.

    :param headers: input dictionary to be sorted.
    """
    signed_headers = []
    for header in headers:
        signed_headers.append(header.lower().strip())
    return sorted(signed_headers)


def sign_v4(method, url, region, headers=None, access_key=None,
            secret_key=None, content_sha256=None):
    """
    Signature version 4.

    :param method: HTTP method used for signature.
    :param url: Final url which needs to be signed.
    :param region: Region should be set to bucket region.
    :param headers: Optional headers for the method.
    :param access_key: Optional access key, if not
       specified no signature is needed.
    :param secret_key: Optional secret key, if not
       specified no signature is needed.
    :param content_sha256: Optional body sha256.
    """

    # If no access key or secret key is provided return headers.
    if not access_key or not secret_key:
        return headers

    if headers is None:
        headers = {}

    if region is None:
        region = 'us-east-1'

    parsed_url = urlsplit(url)
    secure = parsed_url.scheme == 'https'
    if secure:
        content_sha256 = _UNSIGNED_PAYLOAD
    if content_sha256 is None:
        # with no payload, calculate sha256 for 0 length data.
        content_sha256 = get_sha256_hexdigest('')

    host = parsed_url.netloc
    headers['Host'] = host

    date = datetime.utcnow()
    headers['X-Amz-Date'] = date.strftime("%Y%m%dT%H%M%SZ")
    headers['X-Amz-Content-Sha256'] = content_sha256

    headers_to_sign = dict(headers)

    # Remove amazon recommended headers.
    headers_to_sign = ignore_headers(headers_to_sign)

    signed_headers = get_signed_headers(headers_to_sign)
    canonical_req = generate_canonical_request(method,
                                               parsed_url,
                                               headers_to_sign,
                                               content_sha256)
    string_to_sign = generate_string_to_sign(date, region,
                                             canonical_req)
    signing_key = generate_signing_key(date, region, secret_key)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    authorization_header = generate_authorization_header(access_key,
                                                         date,
                                                         region,
                                                         signed_headers,
                                                         signature)

    headers['Authorization'] = authorization_header
    return headers


def generate_canonical_request(method, parsed_url, headers, content_sha256):
    """
    Generate canonical request.

    :param method: HTTP method.
    :param parsed_url: Parsed url is input from :func:`urlsplit`
    :param headers: HTTP header dictionary.
    :param content_sha256: Content sha256 hexdigest string.
    """
    lines = [method, parsed_url.path]

    # Parsed query.
    split_query = parsed_url.query.split('&')
    split_query.sort()
    for i in range(0, len(split_query)):
        if len(split_query[i]) > 0 and '=' not in split_query[i]:
            split_query[i] += '='
    query = '&'.join(split_query)
    lines.append(query)

    # Headers added to canonical request.
    signed_headers = []
    header_lines = []
    for header in headers:
        header = header.lower().strip()
        signed_headers.append(header)
    signed_headers = sorted(signed_headers)

    for header in signed_headers:
        value = headers[header.title()]
        value = str(value).strip()
        header_lines.append(header + ':' + str(value))

    lines = lines + header_lines
    lines.append('')

    lines.append(';'.join(signed_headers))
    lines.append(content_sha256)
    return '\n'.join(lines)


def generate_string_to_sign(date, region, canonical_request):
    """
    Generate string to sign.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param canonical_request: Canonical request generated previously.
    """
    formatted_date_time = date.strftime("%Y%m%dT%H%M%SZ")

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('utf-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()
    scope = generate_scope_string(date, region)

    return '\n'.join([_SIGN_V4_ALGORITHM,
                      formatted_date_time,
                      scope,
                      canonical_request_sha256])


def generate_signing_key(date, region, secret_key):
    """
    Generate signing key.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param secret_key: Secret access key.
    """
    formatted_date = date.strftime("%Y%m%d")

    key1_string = 'AWS4' + secret_key
    key1 = key1_string.encode('utf-8')
    key2 = hmac.new(key1, formatted_date.encode('utf-8'),
                    hashlib.sha256).digest()
    key3 = hmac.new(key2, region.encode('utf-8'), hashlib.sha256).digest()
    key4 = hmac.new(key3, 's3'.encode('utf-8'), hashlib.sha256).digest()

    return hmac.new(key4, 'aws4_request'.encode('utf-8'),
                    hashlib.sha256).digest()


def generate_scope_string(date, region):
    """
    Generate scope string.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    """
    formatted_date = date.strftime("%Y%m%d")
    scope = '/'.join([formatted_date,
                      region,
                      's3',
                      'aws4_request'])
    return scope


def generate_credential_string(access_key, date, region):
    """
    Generate credential string.

    :param access_key: Server access key.
    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    """
    return access_key + '/' + generate_scope_string(date, region)


def generate_authorization_header(access_key, date, region,
                                  signed_headers, signature):
    """
    Generate authorization header.

    :param access_key: Server access key.
    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param signed_headers: Signed headers.
    :param signature: Calculated signature.
    """
    signed_headers_string = ';'.join(signed_headers)
    credential = generate_credential_string(access_key, date, region)
    auth_header = [_SIGN_V4_ALGORITHM, 'Credential=' + credential + ',',
                   'SignedHeaders=' + signed_headers_string + ',',
                   'Signature=' + signature]
    return ' '.join(auth_header)
