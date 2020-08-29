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
import errno
import hashlib
import math
import os
import re
import urllib.parse

from .sse import Sse, SseCustomerKey

# Constants
MAX_MULTIPART_COUNT = 10000  # 10000 parts
MAX_MULTIPART_OBJECT_SIZE = 5 * 1024 * 1024 * 1024 * 1024  # 5TiB
MAX_PART_SIZE = 5 * 1024 * 1024 * 1024  # 5GiB
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
RFC3339NANO = "%Y-%m-%dT%H:%M:%S.%fZ"
RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


def quote(resource, safe='/', encoding=None, errors=None):
    """
    Wrapper to urllib.parse.quote() replacing back to '~' for older python
    versions.
    """
    return urllib.parse.quote(
        resource,
        safe=safe,
        encoding=encoding,
        errors=errors,
    ).replace("%7E", "~")


def queryencode(query, safe='', encoding=None, errors=None):
    """Encode query parameter value."""
    return quote(query, safe, encoding, errors)


def headers_to_strings(headers, titled_key=False):
    """Convert HTTP headers to multi-line string."""
    return "\n".join(
        [
            "{0}: {1}".format(
                key.title() if titled_key else key,
                re.sub(
                    r"Credential=([^/]+)",
                    "Credential=*REDACTED*",
                    re.sub(
                        r"Signature=([0-9a-f]+)",
                        "Signature=*REDACTED*",
                        value,
                    ),
                ) if titled_key else value,
            ) for key, value in headers.items()
        ]
    )


def _validate_sizes(object_size, part_size):
    """Validate object and part size."""
    if part_size > 0:
        if part_size < MIN_PART_SIZE:
            raise ValueError(
                "part size {0} is not supported; minimum allowed 5MiB".format(
                    part_size,
                ),
            )
        if part_size > MAX_PART_SIZE:
            raise ValueError(
                "part size {0} is not supported; minimum allowed 5GiB".format(
                    part_size,
                ),
            )

    if object_size >= 0:
        if object_size > MAX_MULTIPART_OBJECT_SIZE:
            raise ValueError(
                (
                    "object size {0} is not supported; "
                    "maximum allowed 5TiB"
                ).format(object_size),
            )
    elif part_size <= 0:
        raise ValueError(
            "valid part size must be provided when object size is unknown",
        )


def _get_part_info(object_size, part_size):
    """Compute part information for object and part size."""
    _validate_sizes(object_size, part_size)

    if object_size < 0:
        return part_size, -1

    if part_size > 0:
        if part_size > object_size:
            part_size = object_size
        return part_size, math.ceil(object_size / part_size)

    part_size = math.ceil(
        math.ceil(object_size / MAX_MULTIPART_COUNT) / MIN_PART_SIZE,
    ) * MIN_PART_SIZE
    return part_size, math.ceil(object_size / part_size) if part_size else 1


def get_part_info(object_size, part_size):
    """Compute part information for object and part size."""
    part_size, part_count = _get_part_info(object_size, part_size)
    if part_count > MAX_MULTIPART_COUNT:
        raise ValueError(
            (
                "object size {0} and part size {1} "
                "make more than {2} parts for upload"
            ).format(object_size, part_size, MAX_MULTIPART_COUNT),
        )
    return part_size, part_count


def read_part_data(stream, size, part_data=b'', progress=None):
    """Read part data of given size from stream."""
    while len(part_data) < size:
        bytes_to_read = size - len(part_data)
        if bytes_to_read > 16384:
            bytes_to_read = 16384
        data = stream.read(bytes_to_read)
        if not data:
            break  # EOF reached
        part_data += data
        if progress:
            progress.update(len(data))
    return part_data


def makedirs(path):
    """Wrapper of os.makedirs() ignores errno.EEXIST."""
    try:
        if path:
            os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno != errno.EEXIST:
            raise

        if not os.path.isdir(path):
            raise ValueError(
                "path {0} is not a directory".format(path),
            ) from exc


def check_bucket_name(bucket_name, strict=False):
    """Check whether bucket name is valid optional with strict check or not."""

    # Verify bucket name is not empty
    bucket_name = str(bucket_name).strip()
    if not bucket_name:
        raise ValueError('Bucket name cannot be empty.')

    # Verify bucket name length.
    if len(bucket_name) < 3:
        raise ValueError('Bucket name cannot be less than'
                         ' 3 characters.')
    if len(bucket_name) > 63:
        raise ValueError('Bucket name cannot be greater than'
                         ' 63 characters.')

    match = _VALID_IP_ADDRESS.match(bucket_name)
    if match:
        raise ValueError('Bucket name cannot be an ip address')

    unallowed_successive_chars = ['..', '.-', '-.']
    if any(x in bucket_name for x in unallowed_successive_chars):
        raise ValueError('Bucket name contains invalid '
                         'successive chars '
                         + str(unallowed_successive_chars) + '.')

    if strict:
        match = _VALID_BUCKETNAME_STRICT_REGEX.match(bucket_name)
        if (not match) or match.end() != len(bucket_name):
            raise ValueError('Bucket name contains invalid '
                             'characters (strictly enforced).')

    match = _VALID_BUCKETNAME_REGEX.match(bucket_name)
    if (not match) or match.end() != len(bucket_name):
        raise ValueError('Bucket name does not follow S3 standards.'
                         ' Bucket: {0}'.format(bucket_name))


def check_non_empty_string(string):
    """Check whether given string is not empty."""
    try:
        if not string.strip():
            raise ValueError()
    except AttributeError as exc:
        raise TypeError() from exc


def is_valid_policy_type(policy):
    """
    Validate if policy is type str

    :param policy: S3 style Bucket policy.
    :return: True if policy parameter is of a valid type, 'string'.
    Raise :exc:`TypeError` otherwise.
    """
    if not isinstance(policy, (str, bytes)):
        raise TypeError("policy must be str or bytes type")

    check_non_empty_string(policy)

    return True


def is_valid_notification_config(config):
    """
    Validate the notifications config structure

    :param notifications: Dictionary with specific structure.
    :return: True if input is a valid bucket notifications structure.
       Raise :exc:`ValueError` otherwise.
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
                raise ValueError(msg.format(rule))

            if rule.get("Name") not in ["prefix", "suffix"]:
                msg = ("{} - The 'Name' key in a filter rule must be "
                       "either 'prefix' or 'suffix'")
                raise ValueError(msg.format(rule.get("Name")))

    def _check_service_config(config):
        # check keys are valid
        for skey in config.keys():
            if skey not in ("Id", "Arn", "Events", "Filter"):
                msg = "{} is an invalid key for a service configuration item"
                raise ValueError(msg.format(skey))

        # check if "Id" key is present, it should be string or bytes.
        if not isinstance(config.get("Id", ""), str):
            raise ValueError("'Id' key must be a string")

        # check for required keys
        if not config.get("Arn"):
            raise ValueError(
                "Arn key in service config must be present and has to be "
                "non-empty string",
            )

        events = config.get("Events", [])
        if not isinstance(events, list):
            raise ValueError(
                "'Events' must be a list of strings in a service "
                "configuration",
            )
        if not events:
            raise ValueError(
                "At least one event must be specified in a service config",
            )

        for event in events:
            if event not in valid_events:
                msg = "{} is not a valid event. Valid events are: {}"
                raise ValueError(msg.format(event, valid_events))

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
            raise ValueError(msg.format(config["Filter"]))

        rules = config.get(
            "Filter", {}).get("Key", {}).get("FilterRules", [])
        if not isinstance(rules, list) or not rules:
            raise ValueError(msg.format(config["Filter"]))
        _check_filter_rules(rules)

    def _check_value(value, key):
        # check if config values conform
        # first check if value is a list
        if not isinstance(value, list):
            msg = ("The value for key '{}' in the notifications configuration "
                   "must be a list.")
            raise ValueError(msg.format(key))

        for sconfig in value:
            _check_service_config(sconfig)

    # check if config is a dict.
    if not isinstance(config, dict):
        raise TypeError("notifications configuration must be a dictionary")

    if not config:
        raise ValueError(
            "notifications configuration may not be empty"
        )

    for key, value in config.items():
        # check if key names are valid
        if key not in (
                "TopicConfigurations",
                "QueueConfigurations",
                "CloudFunctionConfigurations",
        ):
            raise ValueError((
                '{} is an invalid key '
                'for notifications configuration').format(key))
        _check_value(value, key)

    return True


def check_ssec(sse):
    """Check sse is SseCustomerKey type or not."""
    if sse and not isinstance(sse, SseCustomerKey):
        raise ValueError("SseCustomerKey type is required")


def check_sse(sse):
    """Check sse is Sse type or not."""
    if sse and not isinstance(sse, Sse):
        raise ValueError("Sse type is required")


def md5sum_hash(data):
    """Compute MD5 of data and return hash as Base64 encoded value."""
    if data is None:
        return None

    hasher = hashlib.md5()
    hasher.update(data.encode() if isinstance(data, str) else data)
    md5sum = base64.b64encode(hasher.digest())
    return md5sum.decode() if isinstance(md5sum, bytes) else md5sum


def sha256_hash(data):
    """Compute SHA-256 of data and return hash as hex encoded value."""
    data = data or b""
    hasher = hashlib.sha256()
    hasher.update(data.encode() if isinstance(data, str) else data)
    sha256sum = hasher.hexdigest()
    return sha256sum.decode() if isinstance(sha256sum, bytes) else sha256sum


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
            if isinstance(value, str):
                value.encode('us-ascii')
            value = (
                [str(val) for val in value]
                if isinstance(value, (list, tuple)) else str(value)
            )
        except UnicodeEncodeError as exc:
            raise ValueError(
                'Metadata supports only US-ASCII characters.',
            ) from exc

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


def url_replace(
        url, scheme=None, netloc=None, path=None, query=None, fragment=None
):
    """Return new URL with replaced properties in given URL."""
    return urllib.parse.SplitResult(
        scheme if scheme is not None else url.scheme,
        netloc if netloc is not None else url.netloc,
        path if path is not None else url.path,
        query if query is not None else url.query,
        fragment if fragment is not None else url.fragment,
    )
