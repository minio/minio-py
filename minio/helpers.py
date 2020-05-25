# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017 MinIO, Inc.
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

:copyright: (c) 2015, 2016, 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

# if math.ceil returns an integer and devide two integers returns a float,
# calculate part size will cause errors, so make sure division integers returns
# a float.
from __future__ import absolute_import, division, unicode_literals

import base64
import collections
import errno
import hashlib
import io
import math
import os
import re
# future_str is unicode or str in both Python 2 and 3
from builtins import str as future_str
from datetime import datetime

import pytz

# pylint: disable=redefined-builtin
from .compat import (PYTHON2, basestring, bytes, queryencode, quote, str,
                     urlsplit)
from .error import (InvalidArgumentError, InvalidBucketError,
                    InvalidEndpointError)
from .sse import Sse, SseCustomerKey

# Constants
MAX_MULTIPART_COUNT = 10000  # 10000 parts
MAX_MULTIPART_OBJECT_SIZE = 5 * 1024 * 1024 * 1024 * 1024  # 5TiB
MAX_PART_SIZE = 5 * 1024 * 1024 * 1024  # 5GiB
MAX_POOL_SIZE = 10
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB
DEFAULT_PART_SIZE = MIN_PART_SIZE  # Currently its 5MiB

_VALID_BUCKETNAME_REGEX = re.compile(
    '^[A-Za-z0-9][A-Za-z0-9\\.\\-\\_\\:]{1,61}[A-Za-z0-9]$')
_VALID_BUCKETNAME_STRICT_REGEX = re.compile(
    '^[a-z0-9][a-z0-9\\.\\-]{1,61}[a-z0-9]$')
_VALID_IP_ADDRESS = re.compile(
    r'^(\d+\.){3}\d+$')
_ALLOWED_HOSTNAME_REGEX = re.compile(
    '^((?!-)(?!_)[A-Z_\\d-]{1,63}(?<!-)(?<!_)\\.)*((?!_)(?!-)' +
    '[A-Z_\\d-]{1,63}(?<!-)(?<!_))$',
    re.IGNORECASE)

_EXTRACT_REGION_REGEX = re.compile('s3[.-]?(.+?).amazonaws.com')


def get_s3_region_from_endpoint(endpoint):
    """
    Extracts and returns an AWS S3 region from an endpoint
    of form `s3-ap-southeast-1.amazonaws.com`

    :param endpoint: Endpoint region to be extracted.
    """

    # Extract region by regex search.
    match = _EXTRACT_REGION_REGEX.search(endpoint)
    if not match:
        return None

    # Regex matches, we have found a region.
    region = match.group(1)
    if region == "external-1":
        # Handle special scenario for us-east-1 URL.
        return "us-east-1"

    return region.split(".")[1] if region.startswith("dualstack") else region


def dump_http(method, url, request_headers, response, output_stream):
    """
    Dump all headers and response headers into output_stream.

    :param request_headers: Dictionary of HTTP request headers.
    :param response_headers: Dictionary of HTTP response headers.
    :param output_stream: Stream where the request is being dumped at.
    """

    if response:
        # Write response status code.
        output_stream.write('HTTP/1.1 {0}\n'.format(response.status))

        # Dump all response headers recursively.
        for key, value in response.getheaders().items():
            output_stream.write('{0}: {1}\n'.format(key.title(), value))

        # For all errors write all the available response body.
        if response.status not in [200, 204, 206]:
            output_stream.write('{0}'.format(response.read()))

        # End header.
        output_stream.write('---------END-HTTP---------\n')
        return

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

    for key, value in request_headers.items():
        if key == 'authorization':
            # Redact signature header value from trace logs.
            value = re.sub(
                r'Signature=([[0-9a-f]+)', 'Signature=*REDACTED*',
                value,
            )
        output_stream.write('{0}: {1}\n'.format(key.title(), value))

    # Write a new line.
    output_stream.write('\n')


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


class PartMetadata:
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
    default_read_size = 32768  # 32KiB per read operation.
    chunk = io.BytesIO()
    chunk_size = 0

    while chunk_size < size:
        read_size = default_read_size
        if (size - chunk_size) < default_read_size:
            read_size = size - chunk_size
        current_data = data.read(read_size)
        if not current_data:
            break
        chunk.write(current_data)
        chunk_size += len(current_data)

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
    """Gets AWS S3 endpoint of region."""
    return AWS_S3_ENDPOINT_MAP.get(region, 's3.amazonaws.com')


def get_scheme_host(url):
    """Gets scheme and host of an URL"""
    scheme = url.scheme
    host = url.netloc
    # Strip port 80/443 for HTTP/HTTPS.
    if (scheme == 'http' and url.port == 80) or (
            scheme == 'https' and url.port == 443):
        host = url.hostname

    return scheme, host


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
    scheme, host = get_scheme_host(parsed_url)
    if 's3.amazonaws.com' in host:
        host = get_s3_endpoint(bucket_region)

    url = scheme + '://' + host
    if bucket_name:
        # Save if target url will have buckets which suppport
        # virtual host.
        is_virtual_host_style = is_virtual_host(endpoint_url,
                                                bucket_name)
        if is_virtual_host_style:
            url = scheme + '://' + bucket_name + '.' + host
        else:
            url = scheme + '://' + host + '/' + bucket_name

    url_components = [url]
    url_components.append('/')

    if object_name:
        object_name = encode_object_name(object_name)
        url_components.append(object_name)

    if query:
        ordered_query = collections.OrderedDict(sorted(query.items()))
        query_components = []
        for component_key in ordered_query:
            if isinstance(ordered_query[component_key], list):
                for value in ordered_query[component_key]:
                    query_components.append(component_key + '=' +
                                            queryencode(value))
            else:
                query_components.append(
                    component_key + '=' +
                    queryencode(ordered_query.get(component_key, '')))

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
        if '//' not in endpoint:
            # Having '//' in the beginning of the endpoint enforce
            # urlsplit to consider the endpoint as a netloc according
            # to this quote in docs.python.org/3/library/urllib.parse.html:
            #    Following the syntax specifications in RFC 1808, urlparse
            #    recognizes a netloc only if it is properly introduced by ‘//’.
            #    Otherwise the input is presumed to be a relative URL and thus
            #    to start with a path component.
            endpoint = '//' + endpoint

        url = urlsplit(endpoint)
        if url.scheme:
            raise InvalidEndpointError('Hostname cannot have a scheme.')

        if not url.hostname:
            raise InvalidEndpointError('Hostname cannot be empty.')

        if len(url.hostname) > 255:
            raise InvalidEndpointError('Hostname cannot be greater than 255.')

        if url.hostname[-1] == '.':
            url.hostname = url.hostname[:-1]

        if not _ALLOWED_HOSTNAME_REGEX.match(url.hostname):
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
    is_valid_bucket_name(bucket_name, False)

    parsed_url = urlsplit(endpoint_url)
    # bucket_name can be valid but '.' in the hostname will fail
    # SSL certificate validation. So do not use host-style for
    # such buckets.
    if 'https' in parsed_url.scheme and '.' in bucket_name:
        return False

    return any(host in parsed_url.netloc for host in [
        's3-accelerate.amazonaws.com', 's3.amazonaws.com', 'aliyuncs.com'])


def is_valid_bucket_name(bucket_name, strict):
    """
    Check to see if the ``bucket_name`` complies with the
    restricted DNS naming conventions necessary to allow
    access via virtual-hosting style.

    :param bucket_name: Bucket name in *str*.
    :return: True if the bucket is valid. Raise :exc:`InvalidBucketError`
       otherwise.
    """
    # Verify bucket name is not empty
    bucket_name = str(bucket_name).strip()
    if not bucket_name:
        raise InvalidBucketError('Bucket name cannot be empty.')

    # Verify bucket name length.
    if len(bucket_name) < 3:
        raise InvalidBucketError('Bucket name cannot be less than'
                                 ' 3 characters.')
    if len(bucket_name) > 63:
        raise InvalidBucketError('Bucket name cannot be greater than'
                                 ' 63 characters.')

    match = _VALID_IP_ADDRESS.match(bucket_name)
    if match:
        raise InvalidBucketError('Bucket name cannot be an ip address')

    unallowed_successive_chars = ['..', '.-', '-.']
    if any(x in bucket_name for x in unallowed_successive_chars):
        raise InvalidBucketError('Bucket name contains invalid '
                                 'successive chars '
                                 + str(unallowed_successive_chars) + '.')

    if strict:
        match = _VALID_BUCKETNAME_STRICT_REGEX.match(bucket_name)
        if (not match) or match.end() != len(bucket_name):
            raise InvalidBucketError('Bucket name contains invalid '
                                     'characters (strictly enforced).')

    match = _VALID_BUCKETNAME_REGEX.match(bucket_name)
    if (not match) or match.end() != len(bucket_name):
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
    string_type = basestring if PYTHON2 else str
    if not isinstance(policy, string_type):
        raise TypeError('policy can only be of type str')

    is_non_empty_string(policy)

    return True


def is_valid_notification_config(config):
    """
    Validate the notifications config structure

    :param notifications: Dictionary with specific structure.
    :return: True if input is a valid bucket notifications structure.
       Raise :exc:`InvalidArgumentError` otherwise.
    """

    valid_events = (
        "s3:ObjectAccessed:*",
        "s3:ObjectAccessed:Get",
        "s3:ObjectAccessed:Head",
        "s3:ReducedRedundancyLostObject",
        "s3:ObjectCreated:*",
        "s3:ObjectCreated:Put",
        "s3:ObjectCreated:Post",
        "s3:ObjectCreated:Copy",
        "s3:ObjectCreated:CompleteMultipartUpload",
        "s3:ObjectRemoved:*",
        "s3:ObjectRemoved:Delete",
        "s3:ObjectRemoved:DeleteMarkerCreated",
    )

    def _check_filter_rules(rules):
        for rule in rules:
            if not (rule.get("Name") and rule.get("Value")):
                msg = ("{} - a FilterRule dictionary must have 'Name' "
                       "and 'Value' keys")
                raise InvalidArgumentError(msg.format(rule))

            if rule.get("Name") not in ["prefix", "suffix"]:
                msg = ("{} - The 'Name' key in a filter rule must be "
                       "either 'prefix' or 'suffix'")
                raise InvalidArgumentError(msg.format(rule.get("Name")))

    def _check_service_config(config):
        # check keys are valid
        for skey in config.keys():
            if skey not in ("Id", "Arn", "Events", "Filter"):
                msg = "{} is an invalid key for a service configuration item"
                raise InvalidArgumentError(msg.format(skey))

        # check if "Id" key is present, it should be string or bytes.
        if not isinstance(config.get("Id", ""), basestring):
            raise InvalidArgumentError("'Id' key must be a string")

        # check for required keys
        if not config.get("Arn"):
            raise InvalidArgumentError(
                "Arn key in service config must be present and has to be "
                "non-empty string",
            )

        events = config.get("Events", [])
        if not isinstance(events, list):
            raise InvalidArgumentError(
                "'Events' must be a list of strings in a service "
                "configuration",
            )
        if not events:
            raise InvalidArgumentError(
                "At least one event must be specified in a service config",
            )

        for event in events:
            if event not in valid_events:
                msg = "{} is not a valid event. Valid events are: {}"
                raise InvalidArgumentError(msg.format(event, valid_events))

        if "Filter" not in config:
            return

        msg = ("{} - If a Filter key is given, it must be a "
               "dictionary, the dictionary must have the key 'Key', "
               "and its value must be an object, with a key named "
               "'FilterRules' which must be a non-empty list.")
        if (
                not isinstance(config.get("Filter", {}), dict) or
                not isinstance(config.get("Filter", {}).get("Key", {}), dict)
        ):
            raise InvalidArgumentError(msg.format(config["Filter"]))

        rules = config.get(
            "Filter", {}).get("Key", {}).get("FilterRules", [])
        if not isinstance(rules, list) or not rules:
            raise InvalidArgumentError(msg.format(config["Filter"]))
        _check_filter_rules(rules)

    def _check_value(value, key):
        # check if config values conform
        # first check if value is a list
        if not isinstance(value, list):
            msg = ("The value for key '{}' in the notifications configuration "
                   "must be a list.")
            raise InvalidArgumentError(msg.format(key))

        for sconfig in value:
            _check_service_config(sconfig)

    # check if config is a dict.
    if not isinstance(config, dict):
        raise TypeError("notifications configuration must be a dictionary")

    if not config:
        raise InvalidArgumentError(
            "notifications configuration may not be empty"
        )

    for key, value in config.items():
        # check if key names are valid
        if key not in (
                "TopicConfigurations",
                "QueueConfigurations",
                "CloudFunctionConfigurations",
        ):
            raise InvalidArgumentError((
                '{} is an invalid key '
                'for notifications configuration').format(key))
        _check_value(value, key)

    return True


def is_valid_sse_c_object(sse):
    """
    Validate the SSE object and type

    :param sse: SSE object defined.
    """
    if sse and not isinstance(sse, SseCustomerKey):
        raise InvalidArgumentError(
            "Required type SSE-C object to be passed")


def is_valid_sse_object(sse):
    """
    Validate the SSE object and type

    :param sse: SSE object defined.
    """
    if sse and not isinstance(sse, Sse):
        raise InvalidArgumentError(
            "unsuported type of sse argument in put_object")


def encode_object_name(object_name):
    """
    URL encode input object name.

    :param object_name: Un-encoded object name.
    :return: URL encoded input object name.
    """
    is_non_empty_string(object_name)
    return quote(object_name)


class Hasher:
    """
    Adaptation of hashlib-based hash functions that
    return unicode-encoded hex- and base64-digest
    strings.
    """

    def __init__(self, data, h):
        data = data or b''
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.hasher = h(data)

    @classmethod
    def md5(cls, data=''):
        """Compute MD5 hash."""
        return cls(data, hashlib.md5)

    @classmethod
    def sha256(cls, data=''):
        """Compute SHA-256 hash."""
        return cls(data, hashlib.sha256)

    def update(self, data):
        """Update hash of data."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.hasher.update(data)

    def hexdigest(self):
        """Encode to hex."""
        data = self.hasher.hexdigest()
        return data.decode('utf-8') if isinstance(data, bytes) else data

    def base64digest(self):
        """Encode to base64."""
        data = base64.b64encode(self.hasher.digest())
        return data.decode('utf-8') if isinstance(data, bytes) else data


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


def optimal_part_info(length, part_size):
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

    # honor user configured size
    if part_size != MIN_PART_SIZE:
        part_size_float = float(part_size)
    else:
        # Use floats for part size for all calculations to avoid
        # overflows during float64 to int64 conversions.
        part_size_float = math.ceil(length/MAX_MULTIPART_COUNT)
        part_size_float = (math.ceil(part_size_float/part_size)
                           * part_size)
    # Total parts count.
    total_parts_count = int(math.ceil(length/part_size_float))
    # Part size.
    part_size = int(part_size_float)
    # Last part size.
    last_part_size = length - int(total_parts_count-1)*part_size
    return total_parts_count, part_size, last_part_size


def amzprefix_user_metadata(metadata):
    """
    Return a new metadata dictionary where user defined metadata keys
    are prefixed by "x-amz-meta-".
    """
    meta = dict()
    for key, value in metadata.items():
        # Check if metadata value has US-ASCII encoding since it is
        # the only one supported by HTTP headers. This will show a better
        # exception message when users pass unsupported characters
        # in metadata values.
        try:
            if isinstance(value, future_str):
                value.encode('us-ascii')
        except UnicodeEncodeError:
            raise ValueError('Metadata supports only US-ASCII characters.')

        if (is_amz_header(key) or is_supported_header(key) or
                is_storageclass_header(key)):
            meta[key] = value
        else:
            meta["X-Amz-Meta-" + key] = value
    return meta


def is_amz_header(key):
    """Returns true if amz s3 system defined metadata."""
    key = key.lower()
    return (key.startswith("x-amz-meta") or key == "x-amz-acl" or
            key.startswith("x-amz-server-side-encryption"))


def is_supported_header(key):
    """Returns true if a standard supported header."""

    # Supported headers for object.
    supported_headers = [
        "cache-control",
        "content-encoding",
        "content-type",
        "content-disposition",
        "content-language",
        "x-amz-website-redirect-location",
        # Add more supported headers here.
    ]
    return key.lower() in supported_headers


def is_storageclass_header(key):
    """Returns true if header is a storage class header."""
    return key.lower() == "x-amz-storage-class"


def _iso8601_to_utc_datetime(date_string):
    """
    Convert iso8601 date string into UTC time.

    :param date_string: iso8601 formatted date string.
    :return: :class:`datetime.datetime` with timezone set to UTC
    """

    # Handle timestamps with and without fractional seconds. Some non-AWS
    # vendors (e.g. Dell EMC ECS) are not consistent about always providing
    # fractional seconds.
    try:
        parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%SZ')
    tz_aware_datetime = pytz.utc.localize(parsed_date)
    return tz_aware_datetime
