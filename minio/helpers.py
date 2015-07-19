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
import cgi
import collections
import binascii
import hashlib
import re

from ._compat import compat_str_type, compat_pathname2url

def get_region(hostname):
    if hostname == 's3.amazonaws.com':
        return 'us-east-1'
    if hostname == 's3-ap-northeast-1.amazonaws.com':
        return 'ap-northeast-1'
    if hostname == 's3-ap-southeast-1.amazonaws.com':
        return 'ap-southeast-1'
    if hostname == 's3-ap-southeast-2.amazonaws.com':
        return 'ap-southeast-2'
    if hostname == 's3-eu-central-1.amazonaws.com':
        return 'eu-central-1'
    if hostname == 's3-eu-west-1.amazonaws.com':
        return 'eu-west-1'
    if hostname == 's3-sa-east-1.amazonaws.com':
        return 'sa-east-1'
    if hostname == 's3-external-1.amazonaws.com':
        return 'us-east-1'
    if hostname == 's3-us-west-1.amazonaws.com':
        return 'us-west-1'
    if hostname == 's3-us-west-2.amazonaws.com':
        return 'us-west-2'
    if hostname == 's3.cn-north-1.amazonaws.com.cn':
        return 'cn-north-1'
    if hostname == 's3-fips-us-gov-west-1.amazonaws.com':
        return 'us-gov-west-1'
    return 'milkyway'

def get_target_url(scheme, location, bucket=None, key=None, query=None):
    url_components = [scheme, '://', location, '/']
    # url_components = ['/']
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
                    compat_pathname2url(cgi.escape(str(ordered_query[component_key]))).replace('/', '%2F'))
            query_components.append(''.join(single_component))

        query_string = '&'.join(query_components)
        if query_string is not '':
            url_components.append('?')
            url_components.append(query_string)

    return ''.join(url_components)

def is_valid_url(input_string):
    if not isinstance(input_string, compat_str_type):
        raise TypeError()

    regex = re.compile(
            r'^(?:http)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
            r'localhost|' # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not regex.match(input_string):
        raise ValueError()

def is_valid_bucket_name(input_string):
    is_non_empty_string(input_string)
    if len(input_string) < 3 or len(input_string) > 63:
        raise ValueError()
    if '/' in input_string:
        raise ValueError()
    if not re.match("^[a-z0-9]+[a-z0-9\-]*[a-z0-9]+$", input_string):
        raise ValueError()
    if re.match("/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/", input_string):
        raise ValueError()

def is_non_empty_string(input_string):
    if not isinstance(input_string, compat_str_type):
        raise TypeError()
    if not input_string.strip():
        raise ValueError()

def encode_object_key(input_string):
    is_non_empty_string(input_string)
    return compat_pathname2url(input_string)

def get_sha256(content):
    if len(content) == 0:
        content = b''
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.digest()

def get_md5(content):
    if len(content) == 0:
        content = b''
    hasher = hashlib.md5()
    hasher.update(content)
    return hasher.digest()

def encode_to_base64(content):
    return binascii.b2a_base64(content).strip().decode('utf-8')

def encode_to_hex(content):
    return binascii.hexlify(content)

def calculate_part_size(length):
    minimum_part_size = 1024 * 1024 * 5
    maximum_part_size = 1024 * 1024 * 1024 * 5
    proposed_part_size = length / 9999
    if proposed_part_size > maximum_part_size:
        return maximum_part_size
    return max(minimum_part_size, proposed_part_size)
