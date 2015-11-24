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
Helper functions
"""

import collections
import binascii
import hashlib
import re

from .compat import urlsplit, strtype, urlencode
from .error import InvalidBucketError, InvalidURLError

def get_region(hostname):
    """
    Get region based on hostname, defaults to "us-east-1" if KeyError
    """
    region = {
        's3.amazonaws.com': 'us-east-1',
        's3-ap-northeast-1.amazonaws.com': 'ap-northeast-1',
        's3-ap-southeast-1.amazonaws.com': 'ap-southeast-1',
        's3-ap-southeast-2.amazonaws.com': 'ap-southeast-2',
        's3-eu-central-1.amazonaws.com': 'eu-central-1',
        's3-sa-east-1.amazonaws.com': 'sa-east-1',
        's3-external-1.amazonaws.com': 'us-east-1',
        's3-us-west-1.amazonaws.com': 'us-west-1',
        's3-us-west-2.amazonaws.com': 'us-west-2',
        's3.cn-north-1.amazonaws.com.cn': 'cn-north-1',
        's3-fips-us-gov-west-1.amazonaws.com': 'us-gov-west-1',
    }

    try:
        return region[hostname]
    except KeyError:
        return 'us-east-1'

def get_target_url(url, bucket=None, key=None, query=None):
    """
    Construct target url
    """
    url_components = [url, '/']
    if key is not None:
        key = encode_object_key(key)

    if bucket is not None:
        url_components.append(bucket)
        if key is not None:
            url_components.append('/')
            url_components.append(key)

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

    return ''.join(url_components)

def is_valid_url(endpoint_url):
    """
    Verify the endpoint_url is valid.
    :type endpoint_url: string
    :param endpoint_url: An endpoint_url.  Must have at least a scheme
        and a hostname.
    :return: True if the endpoint url is valid. False otherwise.
    """
    if not isinstance(endpoint_url, strtype):
        raise TypeError('url')

    parts = urlsplit(endpoint_url)
    hostname = parts.hostname
    if hostname is None:
        raise InvalidURLError('url')
    if len(hostname) > 255:
        raise InvalidURLError('url')
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(
        "^((?!-)[A-Z\\d-]{1,63}(?<!-)\\.)*((?!-)[A-Z\\d-]{1,63}(?<!-))$",
        re.IGNORECASE)
    if not allowed.match(hostname):
        raise InvalidURLError('url')

def is_valid_bucket_name(bucket_name):
    """
    Check to see if the ``bucket_name`` complies with the
    restricted DNS naming conventions necessary to allow
    access via virtual-hosting style.

    Even though "." characters are perfectly valid in this DNS
    naming scheme, we are going to punt on any name containing a
    "." character because these will cause SSL cert validation
    problems if we try to use virtual-hosting style addressing.
    """
    validbucket = re.compile('[a-z0-9][a-z0-9\\-]*[a-z0-9]')
    if '.' in bucket_name:
        raise InvalidBucketError('bucket')
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        # Wrong length
        raise InvalidBucketError('bucket')
    if len(bucket_name) == 1:
        if not bucket_name.isalnum():
            raise InvalidBucketError('bucket')
    match = validbucket.match(bucket_name)
    if match is None or match.end() != len(bucket_name):
        raise InvalidBucketError('bucket')

def is_non_empty_string(input_string):
    """
    validate if non empty string
    """
    if not isinstance(input_string, strtype):
        raise TypeError()
    if not input_string.strip():
        raise ValueError()

def encode_object_key(key):
    """
    url encode object key
    """
    is_non_empty_string(key)
    return urlencode(key)

def get_sha256(content):
    """
    calculate sha256 for given content
    """
    if len(content) == 0:
        content = b''
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.digest()

def get_md5(content):
    """
    calculate md5 for given content
    """
    if len(content) == 0:
        content = b''
    hasher = hashlib.md5()
    hasher.update(content)
    return hasher.digest()

def encode_to_base64(content):
    """
    calculate base64 for given content
    """
    return binascii.b2a_base64(content).strip().decode('utf-8')

def encode_to_hex(content):
    """
    calculate hex for given content
    """
    return binascii.hexlify(content)

def calculate_part_size(length):
    """
    calculate optimal part size for multipart uploads
    """
    minimum_part_size = 1024 * 1024 * 5
    maximum_part_size = 1024 * 1024 * 1024 * 5
    proposed_part_size = length / 9999 ## make sure last part has enough buffer
    if proposed_part_size > maximum_part_size:
        return maximum_part_size
    return max(minimum_part_size, proposed_part_size)
