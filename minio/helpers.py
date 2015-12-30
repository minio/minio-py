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
minio.helpers

This module implements all helper functions.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import
import io

import collections
import binascii
import hashlib
import re
import os
import errno

from .compat import urlsplit, basestring, urlencode
from .error import InvalidBucketError, InvalidEndpointError

_VALID_BUCKETNAME_REGEX = re.compile('^[a-z0-9][a-z0-9\\-]+[a-z0-9]$')
_ALLOWED_HOSTNAME_REGEX = re.compile(
    '^((?!-)[A-Z\\d-]{1,63}(?<!-)\\.)*((?!-)[A-Z\\d-]{1,63}(?<!-))$',
    re.IGNORECASE)

def dump_http(method, url, status, request_headers, response_headers, output_stream):
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

    for k in request_headers.keys():
        output_stream.write('{0}: {1}\n'.format(k.title(),
                                                request_headers[k]))

    # Write a new line.
    output_stream.write('\n')

    # Write response status code.
    output_stream.write('HTTP/1.1 {0}\n'.format(status))

    # Dump all response headers recursively.
    for k in response_headers.keys():
        output_stream.write('{0}: {1}\n'.format(k.title(),
                                                response_headers[k]))

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
    :param md5digest: Md5sum digest of the part.
    :param sha256digest: Sha256sum digest of the part.
    :param size: Size of the part.
    """
    def __init__(self, data, md5digest, sha256digest, size):
        self.data = data
        self.md5digest = md5digest
        self.sha256digest = sha256digest
        self.size = size


def parts_manager(data, part_size=5*1024*1024):
    """
    Reads data and provides temporary files of a given size.

    :param data: Input reader object which needs to be saved.
    :param part_size: Individual part number defaults to 5MB.
    :return: Returns :class:`PartMetadata <PartMetadata>`
    """
    tmpdata = io.BytesIO()
    md5hasher = hashlib.md5()
    sha256hasher = hashlib.sha256()
    total_read = 0
    while total_read < part_size:
        current_data = data.read(1024)
        if not current_data or len(current_data) == 0:
            break
        tmpdata.write(current_data)
        md5hasher.update(current_data)
        sha256hasher.update(current_data)
        total_read = total_read + len(current_data)

    return PartMetadata(tmpdata, md5hasher.digest(),
                        sha256hasher.digest(), total_read)


def ignore_headers(headers_to_sign):
    """
    Ignore headers.
    """
    # Excerpts from @lsegal -
    # https://github.com/aws/aws-sdk-js/issues/659#issuecomment-120477258
    #
    #  User-Agent:
    #
    #      This is ignored from signing because signing this causes problems
    #      with generating pre-signed URLs (that are executed by other agents)
    #      or when customers pass requests through proxies, which may modify
    #      the user-agent.
    #
    #  Content-Length:
    #
    #      This is ignored from signing because generating a pre-signed URL
    #      should not provide a content-length constraint, specifically when
    #      vending a S3 pre-signed PUT URL. The corollary to this is that when
    #      sending regular requests (non-pre-signed), the signature contains
    #      a checksum of the body, which implicitly validates the payload
    #      length (since changing the number of bytes would change the
    #      checksum) and therefore this header is not valuable in the
    #      signature.
    #
    #  Content-Type:
    #
    #      Signing this header causes quite a number of problems in browser
    #      environments, where browsers like to modify and normalize the
    #      content-type header in different ways. There is more information
    #      on this in https://github.com/aws/aws-sdk-js/issues/244. Avoiding
    #      this field simplifies logic and reduces the possibility of bugs.
    #
    #  Authorization:
    #
    #      Is skipped for obvious reasons
    ignored_headers = ['Authorization', 'Content-Length',
                       'Content-Type', 'User-Agent']
    for ignored_header in ignored_headers:
        if ignored_header in headers_to_sign:
            del headers_to_sign[ignored_header]

    return headers_to_sign


def get_target_url(endpoint, bucket_name=None, object_name=None, query=None):
    """
    Construct final target url.

    :param endpoint: Target endpoint url where request is served to.
    :param bucket_name: Bucket component for the target url.
    :param object_name: Object component for the target url.
    :param query: Query parameters as a *dict* for the target url.
    :return: Returns final target url as *str*.
    """
    parsed_url = urlsplit(endpoint)
    url = None
    if bucket_name is None:
        url = parsed_url.scheme + '://' + parsed_url.netloc
    else:
        if 'amazonaws.com' in parsed_url.netloc:
            url = (parsed_url.scheme + '://' +
                   bucket_name + '.' + parsed_url.netloc)
        else:
            url = (parsed_url.scheme + '://' +
                   parsed_url.netloc + '/' + bucket_name)

    url_components = [url]
    url_components.append('/')

    if object_name is not None:
        object_name = encode_object_name(object_name)
    if object_name is not None:
        url_components.append(object_name)

    if query is not None:
        ordered_query = collections.OrderedDict(sorted(query.items()))
        query_components = []
        for component_key in ordered_query:
            single_component = [component_key]
            if ordered_query[component_key] is not None:
                single_component.append('=')
                encoded_query = urlencode(
                    str(ordered_query[component_key])).replace(
                        '/',
                        '%2F')
                single_component.append(encoded_query)
            query_components.append(''.join(single_component))

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
    if not isinstance(endpoint, basestring):
        raise TypeError('endpoint')

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

    if hostname.endswith('.amazonaws.com') and \
       (hostname != 's3.amazonaws.com'):
        raise InvalidEndpointError('Amazon S3 hostname should be '
                                   's3.amazonaws.com.')

    return True


def is_valid_bucket_name(bucket_name):
    """
    Check to see if the ``bucket_name`` complies with the
    restricted DNS naming conventions necessary to allow
    access via virtual-hosting style.

    Even though '.' characters are perfectly valid in this DNS
    naming scheme, we are going to punt on any name containing a
    '.' character because these will cause SSL cert validation
    problems if we try to use virtual-hosting style addressing.

    :param bucket_name: Bucket name in *str*.
    :return: True if the bucket is valid. Raise :exc:`InvalidBucketError`
       otherwise.
    """
    # verify bucket name length.
    if len(bucket_name) < 3:
        raise InvalidBucketError('Bucket name cannot be less than'
                                 ' 3 characters.')
    if len(bucket_name) > 63:
        raise InvalidBucketError('Bucket name cannot be more than'
                                 ' 63 characters.')

    match = _VALID_BUCKETNAME_REGEX.match(bucket_name)
    if match is None or match.end() != len(bucket_name):
        raise InvalidBucketError('Bucket name does not follow S3 standards.'
                                 'Bucket: {0}'.format(bucket_name))

    return True


def is_non_empty_string(input_string):
    """
    Validate if non empty string

    :param input_string: Input is a *str*.
    :return: True if input is string. Raise :exc:`Exception` otherwise.
    """
    if not isinstance(input_string, basestring):
        raise TypeError()
    if not input_string.strip():
        raise ValueError()

    return True


def encode_object_name(object_name):
    """
    URL encode input object name.

    :param object_name: Un-encoded object name.
    :return: URL encoded input object name.
    """
    is_non_empty_string(object_name)
    return urlencode(object_name)


def get_sha256(content):
    """
    Calculate sha256 digest of input byte array.

    :param content: Input byte array.
    :return: sha256 digest of input byte array.
    """
    if len(content) == 0:
        content = b''
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.digest()


def get_md5(content):
    """
    Calculate md5 digest of input byte array.

    :param content: Input byte array.
    :return: md5 digest of input byte array.
    """
    if len(content) == 0:
        content = b''
    hasher = hashlib.md5()
    hasher.update(content)
    return hasher.digest()


def encode_to_base64(content):
    """
    Calculate base64 of input byte array.

    :param content: Input byte array.
    :return: base64 encoding of input byte array.
    """
    return binascii.b2a_base64(content).strip().decode('utf-8')


def encode_to_hex(content):
    """
    Calculate hex for input byte array.

    :param content: Input byte array.
    :return: hexlified input byte array.
    """
    return binascii.hexlify(content)


def calculate_part_size(length):
    """
    Calculate optimal part size for multipart uploads.

    :param length: Input length to calculate part size of.
    :return: Optimal part size.
    """
    minimum_part_size = 1024 * 1024 * 5
    maximum_part_size = 1024 * 1024 * 1024 * 5
    if length == -1:
        return maximum_part_size
    # make sure last part has enough buffer
    proposed_part_size = length / 9999
    if proposed_part_size > maximum_part_size:
        return maximum_part_size
    return max(minimum_part_size, proposed_part_size)
