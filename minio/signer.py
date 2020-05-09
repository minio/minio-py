# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015-2020 MinIO, Inc.
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

:copyright: (c) 2015 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import collections
import hashlib
import hmac
from datetime import datetime

from .compat import queryencode, urlsplit
from .error import InvalidArgumentError
from .fold_case_dict import FoldCaseDict
from .helpers import get_sha256_hexdigest

# Signature version '4' algorithm.
_SIGN_V4_ALGORITHM = 'AWS4-HMAC-SHA256'

# Hardcoded S3 header value for X-Amz-Content-Sha256
_UNSIGNED_PAYLOAD = u'UNSIGNED-PAYLOAD'

# Hardcoded service name for pre-signed S3 urls
_PRESIGNED_SERVICE_NAME = "s3"

# Default service name for all signature
_DEFAULT_SERVICE_NAME = "s3"


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


def presign_v4(method, url, credentials,
               region=None, headers=None, expires=None,
               response_headers=None, request_date=None):
    """
    Calculates signature version '4' for regular presigned URLs.

    :param method: Method to be presigned examples 'PUT', 'GET'.
    :param url: URL to be presigned.
    :param credentials: Credentials object with your AWS s3 account info.
    :param region: region of the bucket, it is optional.
    :param headers: any additional HTTP request headers to
       be presigned, it is optional.
    :param expires: final expiration of the generated URL. Maximum is 7days.
    :param response_headers: Specify additional query string parameters.
    :param request_date: the date of the request.
    """

    # Validate input arguments.
    if not credentials.get().access_key or not credentials.get().secret_key:
        raise InvalidArgumentError('Invalid access_key and secret_key.')

    region = region or 'us-east-1'
    headers = headers or {}
    expires = expires or '604800'
    request_date = request_date or datetime.utcnow()

    # If a sha256sum is known, add to headers to include with signature
    content_hash_hex = _UNSIGNED_PAYLOAD
    for k in headers:
        if k.lower() == 'x-amz-content-sha256':
            content_hash_hex = headers[k] or _UNSIGNED_PAYLOAD
            del headers[k]
            break

    parsed_url = urlsplit(url)
    host = remove_default_port(parsed_url)
    headers['Host'] = host
    iso8601_date = request_date.strftime("%Y%m%dT%H%M%SZ")

    headers_to_sign = headers
    # Construct queries.
    query = {}
    query['X-Amz-Algorithm'] = _SIGN_V4_ALGORITHM
    query['X-Amz-Credential'] = generate_credential_string(
        credentials.get().access_key,
        request_date,
        region,
        _PRESIGNED_SERVICE_NAME,
    )
    query['X-Amz-Date'] = iso8601_date
    query['X-Amz-Expires'] = str(expires)
    if credentials.get().session_token:
        query['X-Amz-Security-Token'] = credentials.get().session_token

    signed_headers = get_signed_headers(headers_to_sign)
    query['X-Amz-SignedHeaders'] = ';'.join(signed_headers)

    if response_headers:
        query.update(response_headers)

    # URL components.
    url_components = [parsed_url.geturl()]
    ordered_query = collections.OrderedDict(sorted(query.items()))
    query_components = []
    for component_key in ordered_query:
        single_component = [component_key, '=']
        if ordered_query[component_key]:
            single_component.append(queryencode(ordered_query[component_key]))
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
                                                   signed_headers,
                                                   content_hash_hex)
    string_to_sign = generate_string_to_sign(request_date, region,
                                             canonical_request,
                                             _PRESIGNED_SERVICE_NAME)
    signing_key = generate_signing_key(request_date, region,
                                       credentials.get().secret_key)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()
    new_parsed_url = urlsplit(new_url + "&X-Amz-Signature="+signature)
    return new_parsed_url.geturl()


def get_signed_headers(headers):
    """
    Get signed headers.

    :param headers: input dictionary to be sorted.
    """
    return sorted([h.lower().strip() for h in headers])


def sign_v4(method, url, region, headers=None,
            credentials=None,
            content_sha256=None,
            request_datetime=None,
            service_name=_DEFAULT_SERVICE_NAME
            ):
    """
    Signature version 4.

    :param method: HTTP method used for signature.
    :param url: Final url which needs to be signed.
    :param region: Region should be set to bucket region.
    :param headers: Optional headers for the method.
    :param credentials: Optional Credentials object with your AWS s3 account
                        info.
    :param content_sha256: Optional body sha256.
    :param request_datetime: Optional request date/time
    :param service_name: Optional service to sign request for (defaults to S3)
    """

    # If no access key or secret key is provided return headers.
    if not credentials.get().access_key or not credentials.get().secret_key:
        return headers

    headers = headers or FoldCaseDict()
    region = region or 'us-east-1'

    parsed_url = urlsplit(url)
    secure = parsed_url.scheme == 'https'
    if secure and not content_sha256:
        content_sha256 = _UNSIGNED_PAYLOAD
    content_sha256 = content_sha256 or get_sha256_hexdigest('')

    host = remove_default_port(parsed_url)
    headers['Host'] = host

    request_datetime = request_datetime or datetime.utcnow()

    headers['X-Amz-Date'] = request_datetime.strftime("%Y%m%dT%H%M%SZ")
    headers['X-Amz-Content-Sha256'] = content_sha256
    if credentials.get().session_token:
        headers['X-Amz-Security-Token'] = credentials.get().session_token

    headers_to_sign = headers

    signed_headers = get_signed_headers(headers_to_sign)
    canonical_req = generate_canonical_request(method,
                                               parsed_url,
                                               headers_to_sign,
                                               signed_headers,
                                               content_sha256
                                               )

    string_to_sign = generate_string_to_sign(request_datetime, region,
                                             canonical_req, service_name)
    signing_key = generate_signing_key(
        request_datetime, region, credentials.get().secret_key, service_name)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    authorization_header = generate_authorization_header(
        credentials.get().access_key, request_datetime, region, signed_headers,
        signature, service_name)

    headers['Authorization'] = authorization_header
    return headers


def generate_canonical_request(method, parsed_url, headers, signed_headers,
                               content_sha256):
    """
    Generate canonical request.

    :param method: HTTP method.
    :param parsed_url: Parsed url is input from :func:`urlsplit`
    :param headers: HTTP header dictionary.
    :param content_sha256: Content sha256 hexdigest string.
    """
    # Should not encode ~. Decode it back if present.
    parsed_url_path = parsed_url.path.replace("%7E", "~")
    parsed_url_query = parsed_url.query.replace("%7E", "~")
    lines = [method, parsed_url_path, parsed_url_query]

    # Headers added to canonical request.
    header_lines = []
    for header in signed_headers:
        value = headers[header.title()]
        value = str(value).strip()
        header_lines.append(header + ':' + value)

    lines = lines + header_lines
    lines.append('')

    lines.append(';'.join(signed_headers))
    lines.append(content_sha256)
    return '\n'.join(lines)


def generate_string_to_sign(date, region, canonical_request,
                            service_name=_DEFAULT_SERVICE_NAME):
    """
    Generate string to sign.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param canonical_request: Canonical request generated previously.
    :param service_name: Service to scope request for.
    """
    formatted_date_time = date.strftime("%Y%m%dT%H%M%SZ")

    canonical_request_hasher = hashlib.sha256()
    canonical_request_hasher.update(canonical_request.encode('utf-8'))
    canonical_request_sha256 = canonical_request_hasher.hexdigest()
    scope = generate_scope_string(date, region, service_name)

    return '\n'.join([_SIGN_V4_ALGORITHM,
                      formatted_date_time,
                      scope,
                      canonical_request_sha256])


def generate_signing_key(date, region, secret_key,
                         service_name=_DEFAULT_SERVICE_NAME):
    """
    Generate signing key.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param secret_key: Secret access key.
    :param service_name: The signing key is scoped to a service e.g. s3
    """
    formatted_date = date.strftime("%Y%m%d")

    key1_string = 'AWS4' + secret_key
    key1 = key1_string.encode('utf-8')
    key2 = hmac.new(key1, formatted_date.encode('utf-8'),
                    hashlib.sha256).digest()
    key3 = hmac.new(key2, region.encode('utf-8'), hashlib.sha256).digest()
    key4 = hmac.new(key3, service_name.encode(
        'utf-8'), hashlib.sha256).digest()

    return hmac.new(key4, 'aws4_request'.encode('utf-8'),
                    hashlib.sha256).digest()


def generate_scope_string(date, region, service_name):
    """
    Generate scope string.

    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param service_name: Service for scope string, e.g., "s3".
    """
    formatted_date = date.strftime("%Y%m%d")
    scope = '/'.join([formatted_date,
                      region,
                      service_name,
                      'aws4_request'])
    return scope


def generate_credential_string(access_key, date, region,
                               service_name=_DEFAULT_SERVICE_NAME):
    """
    Generate credential string.

    :param access_key: Server access key.
    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param service_name: Service to scope credentials to.
    """
    return access_key + '/' + generate_scope_string(date, region, service_name)


def generate_authorization_header(access_key, date, region,
                                  signed_headers, signature,
                                  service_name=_DEFAULT_SERVICE_NAME):
    """
    Generate authorization header.

    :param access_key: Server access key.
    :param date: Date is input from :meth:`datetime.datetime`
    :param region: Region should be set to bucket region.
    :param signed_headers: Signed headers.
    :param signature: Calculated signature.
    :param service_name: Optional service to sign request for.
    """
    signed_headers_string = ';'.join(signed_headers)
    credential = generate_credential_string(
        access_key, date, region, service_name)
    auth_header = [_SIGN_V4_ALGORITHM, 'Credential=' + credential + ',',
                   'SignedHeaders=' + signed_headers_string + ',',
                   'Signature=' + signature]
    return ' '.join(auth_header)


def remove_default_port(parsed_url):
    """Remove default port in URL."""
    default_ports = {
        'http': 80,
        'https': 443
    }
    if any(parsed_url.scheme == scheme and parsed_url.port == port
           for scheme, port in default_ports.items()):
        # omit default port (i.e. 80 or 443)
        host = parsed_url.hostname
    else:
        host = parsed_url.netloc
    return host
