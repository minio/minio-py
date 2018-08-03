# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017 Minio, Inc.
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
minio.helpers

This module implements all helper functions.

:copyright: (c) 2015, 2016, 2017 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import
# if math.ceil returns an integer and devide two integers returns a float, calculate
# part size will cause errors, so make sure division integers returns a float.
from __future__ import division
import io

import collections
import base64
import hashlib
import re
import os
import errno
import math

from .compat import (urlsplit, urlencode, queryencode,
                     str, bytes, basestring, _is_py3, _is_py2)
from .error import (InvalidBucketError, InvalidEndpointError,
                    InvalidArgumentError)

# Constants
MAX_MULTIPART_COUNT = 10000 # 10000 parts
MAX_MULTIPART_OBJECT_SIZE = 5 * 1024 * 1024 * 1024 * 1024  # 5TiB
MAX_POOL_SIZE = 10
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB

_VALID_BUCKETNAME_REGEX = re.compile('^[a-z0-9][a-z0-9\\.\\-]+[a-z0-9]$')
_ALLOWED_HOSTNAME_REGEX = re.compile(
    '^((?!-)[A-Z\\d-]{1,63}(?<!-)\\.)*((?!-)[A-Z\\d-]{1,63}(?<!-))$',
    re.IGNORECASE)

_EXTRACT_REGION_REGEX = re.compile('s3[.-]?(.+?).amazonaws.com')

def get_s3_region_from_endpoint(endpoint):
    """
    Extracts and returns an AWS S3 region from an endpoint
    of form `s3-ap-southeast-1.amazonaws.com`

    :param endpoint: Endpoint region to be extracted.
    """

    # Extract region by regex search.
    m = _EXTRACT_REGION_REGEX.search(endpoint)
    if m:
        # Regex matches, we have found a region.
        region = m.group(1)
        if region == 'external-1':
            # Handle special scenario for us-east-1 URL.
            return 'us-east-1'
        if region.startswith('dualstack'):
            # Handle special scenario for dualstack URL.
            return region.split('.')[1]
        return region

    # No regex matches return None.
    return None

def dump_http(method, url, request_headers, response, output_stream):
    """
    Dump all headers and response headers into output_stream.

    :param request_headers: Dictionary of HTTP request headers.
    :param response_headers: Dictionary of HTTP response headers.
    :param output_stream: Stream where the request is being dumped at.
    """

    # Start header.
    output_stream.write('---------START-HTTP---------\n')

    # Get parsed url.
    parsed_url = urlsplit(url)

    # Dump all request headers recursively.
    http_path = parsed_url.path
    if parsed_url.query:
        http_path = http_path + '?' + parsed_url.query

    output_stream.write('{0} {1} HTTP/1.1\n'.format(method,
                                                    http_path))

    for k, v in list(request_headers.items()):
        if k is 'authorization':
            # Redact signature header value from trace logs.
            v = re.sub(r'Signature=([[0-9a-f]+)', 'Signature=*REDACTED*', v)
        output_stream.write('{0}: {1}\n'.format(k.title(), v))

    # Write a new line.
    output_stream.write('\n')

    # Write response status code.
    output_stream.write('HTTP/1.1 {0}\n'.format(response.status))

    # Dump all response headers recursively.
    for k, v in list(response.getheaders().items()):
        output_stream.write('{0}: {1}\n'.format(k.title(), v))

    # For all errors write all the available response body.
    if response.status != 200 and \
       response.status != 204 and response.status != 206:
        output_stream.write('{0}'.format(response.read()))

    # End header.
    output_stream.write('---------END-HTTP---------\n')

def mkdir_p(path):
    """
    Recursively creates parent and sub directories.

    :param path:
    """
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

class PartMetadata(object):
    """
    Parts manager split parts metadata :class:`PartMetadata <PartMetadata>`.

    :param data: Part writer object backed by temporary file.
    :param md5_hex: MD5 hash in hex format.
    :param sha256_hex: Sha256 hash in hex format.
    :param size: Size of the part.
    """
    def __init__(self, data, md5_hex, sha256_hex, size):
        self.data = data
        self.md5_hex = md5_hex
        self.sha256_hex = sha256_hex
        self.size = size

def read_full(data, size):
    """
    read_full reads exactly `size` bytes from reader. returns
    `size` bytes.

    :param data: Input stream to read from.
    :param size: Number of bytes to read from `data`.
    :return: Returns :bytes:`part_data`
    """
    default_read_size = 32768 # 32KiB per read operation.
    chunk = io.BytesIO()
    chunk_size = 0

    while chunk_size < size:
        read_size = default_read_size
        if (size - chunk_size) < default_read_size:
            read_size = size - chunk_size
        current_data = data.read(read_size)
        if not current_data or len(current_data) == 0:
            break
        chunk.write(current_data)
        chunk_size+= len(current_data)

    return chunk.getvalue()

AWS_S3_ENDPOINT_MAP = {
    'us-east-1': 's3.amazonaws.com',
    'us-east-2': 's3-us-east-2.amazonaws.com',
    'us-west-2': 's3-us-west-2.amazonaws.com',
    'us-west-1': 's3-us-west-1.amazonaws.com',
    'ca-central-1': 's3.ca-central-1.amazonaws.com',
    'eu-west-1': 's3-eu-west-1.amazonaws.com',
    'eu-west-2': 's3-eu-west-2.amazonaws.com',
    'sa-east-1': 's3-sa-east-1.amazonaws.com',
    'eu-central-1': 's3-eu-central-1.amazonaws.com',
    'ap-south-1': 's3.ap-south-1.amazonaws.com',
    'ap-southeast-1': 's3-ap-southeast-1.amazonaws.com',
    'ap-southeast-2': 's3-ap-southeast-2.amazonaws.com',
    'ap-northeast-1': 's3-ap-northeast-1.amazonaws.com',
    'ap-northeast-2': 's3-ap-northeast-2.amazonaws.com',
    'cn-north-1': 's3.cn-north-1.amazonaws.com.cn'
}

def get_s3_endpoint(region):
    return AWS_S3_ENDPOINT_MAP.get(region, 's3.amazonaws.com')

def get_target_url(endpoint_url, bucket_name=None, object_name=None,
                   bucket_region='us-east-1', query=None):
    """
    Construct final target url.

    :param endpoint_url: Target endpoint url where request is served to.
    :param bucket_name: Bucket component for the target url.
    :param object_name: Object component for the target url.
    :param bucket_region: Bucket region for the target url.
    :param query: Query parameters as a *dict* for the target url.
    :return: Returns final target url as *str*.
    """
    # New url
    url = None

    # Parse url
    parsed_url = urlsplit(endpoint_url)

    # Get new host, scheme.
    scheme = parsed_url.scheme
    host = parsed_url.netloc

    # Strip 80/443 ports since curl & browsers do not
    # send them in Host header.
    if (scheme == 'http' and parsed_url.port == 80) or\
       (scheme == 'https' and parsed_url.port == 443):
        host = parsed_url.hostname

    if 's3.amazonaws.com' in host:
        host = get_s3_endpoint(bucket_region)

    url = scheme + '://' + host
    if bucket_name:
        # Save if target url will have buckets which suppport
        # virtual host.
        is_virtual_host_style = is_virtual_host(endpoint_url,
                                                bucket_name)
        if is_virtual_host_style:
            url = (scheme + '://' + bucket_name + '.' + host)
        else:
            url = (scheme + '://' + host + '/' + bucket_name)

    url_components = [url]
    url_components.append('/')

    if object_name:
        object_name = encode_object_name(object_name)
        url_components.append(object_name)

    if query:
        ordered_query = collections.OrderedDict(sorted(query.items()))
        query_components = []
        for component_key in ordered_query:
            if ordered_query[component_key] is not None:
                if isinstance(ordered_query[component_key], list):
                    for value in ordered_query[component_key]:
                        query_components.append(component_key+'='+
                                                queryencode(value))
                else:
                    query_components.append(
                        component_key+'='+
                        queryencode(
                            ordered_query[component_key]
                        )
                    )
            else:
                query_components.append(component_key)

        query_string = '&'.join(query_components)
        if query_string:
            url_components.append('?')
            url_components.append(query_string)

    return ''.join(url_components)


def is_valid_endpoint(endpoint):
    """
    Verify if endpoint is valid.

    :type endpoint: string
    :param endpoint: An endpoint. Must have at least a scheme and a hostname.
    :return: True if the endpoint is valid. Raise :exc:`InvalidEndpointError`
       otherwise.
    """
    try:
        if urlsplit(endpoint).scheme:
            raise InvalidEndpointError('Hostname cannot have a scheme.')

        hostname = endpoint.split(':')[0]
        if hostname is None:
            raise InvalidEndpointError('Hostname cannot be empty.')

        if len(hostname) > 255:
            raise InvalidEndpointError('Hostname cannot be greater than 255.')

        if hostname[-1] == '.':
            hostname = hostname[:-1]

        if not _ALLOWED_HOSTNAME_REGEX.match(hostname):
            raise InvalidEndpointError('Hostname does not meet URL standards.')

    except AttributeError as error:
        raise TypeError(error)

    return True

def is_virtual_host(endpoint_url, bucket_name):
    """
    Check to see if the ``bucket_name`` can be part of virtual host
    style.

    :param endpoint_url: Endpoint url which will be used for virtual host.
    :param bucket_name: Bucket name to be validated against.
    """
    is_valid_bucket_name(bucket_name)

    parsed_url = urlsplit(endpoint_url)
    # bucket_name can be valid but '.' in the hostname will fail
    # SSL certificate validation. So do not use host-style for
    # such buckets.
    if 'https' in parsed_url.scheme and '.' in bucket_name:
        return False
    for host in ['s3.amazonaws.com', 'aliyuncs.com']:
        if host in parsed_url.netloc:
            return True
    return False

def is_valid_bucket_name(bucket_name):
    """
    Check to see if the ``bucket_name`` complies with the
    restricted DNS naming conventions necessary to allow
    access via virtual-hosting style.

    :param bucket_name: Bucket name in *str*.
    :return: True if the bucket is valid. Raise :exc:`InvalidBucketError`
       otherwise.
    """
    # Verify bucket name length.
    if len(bucket_name) < 3:
        raise InvalidBucketError('Bucket name cannot be less than'
                                 ' 3 characters.')
    if len(bucket_name) > 63:
        raise InvalidBucketError('Bucket name cannot be more than'
                                 ' 63 characters.')
    if '..' in bucket_name:
        raise InvalidBucketError('Bucket name cannot have successive'
                                 ' periods.')

    match = _VALID_BUCKETNAME_REGEX.match(bucket_name)
    if match is None or match.end() != len(bucket_name):
        raise InvalidBucketError('Bucket name does not follow S3 standards.'
                                 ' Bucket: {0}'.format(bucket_name))

    return True


def is_non_empty_string(input_string):
    """
    Validate if non empty string

    :param input_string: Input is a *str*.
    :return: True if input is string and non empty.
       Raise :exc:`Exception` otherwise.
    """
    try:
        if not input_string.strip():
            raise ValueError()
    except AttributeError as error:
        raise TypeError(error)

    return True

def is_valid_policy_type(policy):
    """
    Validate if policy is type str

    :param policy: S3 style Bucket policy.
    :return: True if policy parameter is of a valid type, 'string'.
    Raise :exc:`TypeError` otherwise.
    """
    if _is_py3:
        string_type = str,
    elif _is_py2:
        string_type = basestring

    if not isinstance(policy, string_type):
        raise TypeError('policy can only be of type str')

    is_non_empty_string(policy)

    return True

def is_valid_bucket_notification_config(notifications):
    """
    Validate the notifications config structure

    :param notifications: Dictionary with specific structure.
    :return: True if input is a valid bucket notifications structure.
       Raise :exc:`InvalidArgumentError` otherwise.
    """
    # check if notifications is a dict.
    if not isinstance(notifications, dict):
        raise TypeError('notifications configuration must be a dictionary')

    if len(notifications) == 0:
        raise InvalidArgumentError(
            'notifications configuration may not be empty'
        )

    VALID_NOTIFICATION_KEYS = set([
        "TopicConfigurations",
        "QueueConfigurations",
        "CloudFunctionConfigurations",
    ])

    VALID_SERVICE_CONFIG_KEYS = set([
        'Id',
        'Arn',
        'Events',
        'Filter',
    ])

    NOTIFICATION_EVENTS = set([
        's3:ReducedRedundancyLostObject',
        's3:ObjectCreated:*',
        's3:ObjectCreated:Put',
        's3:ObjectCreated:Post',
        's3:ObjectCreated:Copy',
        's3:ObjectCreated:CompleteMultipartUpload',
        's3:ObjectRemoved:*',
        's3:ObjectRemoved:Delete',
        's3:ObjectRemoved:DeleteMarkerCreated',
    ])

    for key, value in notifications.items():
        # check if key names are valid
        if key not in VALID_NOTIFICATION_KEYS:
            raise InvalidArgumentError((
                '{} is an invalid key '
                'for notifications configuration').format(key))

        # check if config values conform
        # first check if value is a list
        if not isinstance(value, list):
            raise InvalidArgumentError((
                'The value for key "{}" in the notifications '
                'configuration must be a list.').format(key))

        for service_config in value:
            # check type matches
            if not isinstance(service_config, dict):
                raise InvalidArgumentError((
                    'Each service configuration item for "{}" must be a '
                    'dictionary').format(key))

            # check keys are valid
            for skey in service_config.keys():
                if skey not in VALID_SERVICE_CONFIG_KEYS:
                    raise InvalidArgumentError((
                        '{} is an invalid key for a service '
                        'configuration item').format(skey))

            # check for required keys
            arn = service_config.get('Arn', '')
            if arn == '':
                raise InvalidArgumentError(
                    'Arn key in service config must be present and has to be '
                    'non-empty string'
                )
            events = service_config.get('Events', [])
            if len(events) < 1:
                raise InvalidArgumentError(
                    'At least one event must be specified in a service config'
                )
            if not isinstance(events, list):
                raise InvalidArgumentError('"Events" must be a list of strings '
                                           'in a service configuration')

            # check if 'Id' key is present, it should be string or bytes.
            if not isinstance(service_config.get('Id', ''), basestring):
                raise InvalidArgumentError('"Id" key must be a string')

            for event in events:
                if event not in NOTIFICATION_EVENTS:
                    raise InvalidArgumentError(
                        '{} is not a valid event. Valid '
                        'events are: {}'.format(event, NOTIFICATION_EVENTS))

            if 'Filter' in service_config:
                exception_msg = (
                    '{} - If a Filter key is given, it must be a '
                    'dictionary, the dictionary must have the '
                    'key "Key", and its value must be an object, with '
                    'a key named "FilterRules" which must be a non-empty list.'
                ).format(
                    service_config['Filter']
                )
                try:
                    filter_rules = service_config.get('Filter', {}).get(
                        'Key', {}).get('FilterRules', [])
                    if not isinstance(filter_rules, list):
                        raise InvalidArgumentError(exception_msg)
                    if len(filter_rules) < 1:
                        raise InvalidArgumentError(exception_msg)
                except AttributeError:
                    raise InvalidArgumentError(exception_msg)
                for filter_rule in filter_rules:
                    try:
                        name = filter_rule['Name']
                        value = filter_rule['Value']
                    except KeyError:
                        raise InvalidArgumentError((
                            '{} - a FilterRule dictionary must have "Name" '
                             'and "Value" keys').format(filter_rule))

                    if name not in ['prefix', 'suffix']:
                        raise InvalidArgumentError((
                            '{} - The "Name" key in a filter rule must be '
                             'either "prefix" or "suffix"').format(name))

    return True

def is_valid_sse_c_object(sse=None):
    """
    Validate the SSE object and type

    :param sse: SSE object defined.
    """
    if sse and sse.type() != "SSE-C":
            raise InvalidArgumentError("Required type SSE-C object to be passed")

def is_valid_sse_object(sse):
    """
    Validate the SSE object and type

    :param sse: SSE object defined.
    """
    if sse and sse.type() != "SSE-C" and sse.type() != "SSE-KMS" and sse.type() != "SSE-S3":
        raise InvalidArgumentError("unsuported type of sse argument in put_object")

def is_valid_source_sse_object(sse):
    """
    Validate the SSE object and type

    :param sse: SSE object defined.
    """
    if sse and sse.type() != "copy_SSE-C":
        raise InvalidArgumentError("Required type copy_SSE-C object to be passed")

def encode_object_name(object_name):
    """
    URL encode input object name.

    :param object_name: Un-encoded object name.
    :return: URL encoded input object name.
    """
    is_non_empty_string(object_name)
    return urlencode(object_name)

class Hasher(object):
    """
    Adaptation of hashlib-based hash functions that
    return unicode-encoded hex- and base64-digest
    strings.
    """
    def __init__(self, data, h):
        if data is None:
            data = b''
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.h = h(data)

    @classmethod
    def md5(cls, data=''):
        return cls(data, hashlib.md5)

    @classmethod
    def sha256(cls, data=''):
        return cls(data, hashlib.sha256)

    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.h.update(data)

    def hexdigest(self):
        r = self.h.hexdigest()
        return r.decode('utf-8') if isinstance(r, bytes) else r

    def base64digest(self):
        r = base64.b64encode(self.h.digest())
        return r.decode('utf-8') if isinstance(r, bytes) else r


def get_sha256_hexdigest(content):
    """
    Calculate sha256 hexdigest of content.

    :param content: Input str or bytes. If the type is `str` we encode
    it to UTF8 first.

    :return: sha256 digest encoded as hexadecimal `str`.

    """
    return Hasher.sha256(content).hexdigest()


def get_md5_base64digest(content):
    """Calculate md5sum and return digest as base64 encoded string.

    :param content: Input str or bytes. If the type is `str` we encode
    it to UTF8 and calculate md5sum.

    :return: md5 digest encoded to base64 `str`.

    """
    return Hasher.md5(content).base64digest()


def optimal_part_info(length):
    """
    Calculate optimal part size for multipart uploads.

    :param length: Input length to calculate part size of.
    :return: Optimal part size.
    """
    # object size is '-1' set it to 5TiB.
    if length == -1:
        length = MAX_MULTIPART_OBJECT_SIZE
    if length > MAX_MULTIPART_OBJECT_SIZE:
        raise InvalidArgumentError('Input content size is bigger '
                                   ' than allowed maximum of 5TiB.')

    # Use floats for part size for all calculations to avoid
    # overflows during float64 to int64 conversions.
    part_size_float = math.ceil(length/MAX_MULTIPART_COUNT)
    part_size_float = (math.ceil(part_size_float/MIN_PART_SIZE)
                       * MIN_PART_SIZE)
    # Total parts count.
    total_parts_count = int(math.ceil(length/part_size_float))
    # Part size.
    part_size = int(part_size_float)
    # Last part size.
    last_part_size = length - int(total_parts_count-1)*part_size
    return total_parts_count, part_size, last_part_size

# return a new metadata dictionary where user defined metadata keys
# are prefixed by "x-amz-meta-"
def amzprefix_user_metadata(metadata):
    m = dict()
    for k,v in metadata.items():
       if is_amz_header(k) or is_supported_header(k) or is_storageclass_header(k):
            m[k] = v
       else:
            m["X-Amz-Meta-" + k] = v
    return m

# returns true if amz s3 system defined metadata
def is_amz_header(key):
    key = key.lower()
    return key.startswith("x-amz-meta") or key == "x-amz-acl" or key.startswith("x-amz-server-side-encryption")

# returns true if a standard supported header
def is_supported_header(key):
    ## Supported headers for object.
    supported_headers = [
	   "cache-control",
	   "content-encoding",
	   "content-disposition",
	   "content-language",
	   "x-amz-website-redirect-location",
            ## Add more supported headers here.
        ]
    return key.lower() in supported_headers

# returns true if header is a storage class header
def is_storageclass_header(key):
    return key.lower() == "x-amz-storage-class"
