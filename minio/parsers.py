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
minio.parsers
~~~~~~~~~~~~~~~~~~~

This module contains core API parsers.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

# standard.
from xml.etree import cElementTree
from xml.etree.cElementTree import ParseError

from datetime import datetime

# dependencies.
import pytz

# minio specific.
from .error import InvalidXMLError
from .compat import urldecode
from .definitions import (Object, Bucket, IncompleteUpload,
                          UploadPart, MultipartUploadResult)

if hasattr(cElementTree, 'ParseError'):
    _ETREE_EXCEPTIONS = (ParseError, AttributeError, ValueError, TypeError)
else:
    _ETREE_EXCEPTIONS = (SyntaxError, AttributeError, ValueError, TypeError)

_S3_NS = {'s3' : 'http://s3.amazonaws.com/doc/2006-03-01/'}


def get_element_text(element, xpath, ns=_S3_NS):
    """
    Get element text for a given xpath.

    :param element: Element xml object.
    :param xpath: XML attribute inside the element.
    :param ns: Necessary namespace to look for.
    """
    return element.find(xpath, ns).text

def parse_multipart_upload_result(data):
    """
    Parser for complete multipart upload response.

    :param data: Respone data for complete multipart upload.
    :return: :class:`MultipartUploadResult <MultipartUploadResult>`.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"CompleteMultipartUploadResult" XML is not parsable. '
                              'Message: {0}'.format(error.message))
    try:
        bucket_name = get_element_text(root, 's3:Bucket')
        object_name = get_element_text(root, 's3:Key')
        location = get_element_text(root, 's3:Location')
        etag = get_element_text(root, 's3:ETag')
        # Strip off quotes from begining and the end.
        if etag.startswith('"') and etag.endswith('"'):
            etag = etag[len('"'):]
            etag = etag[:-len('"')]

        return MultipartUploadResult(bucket_name, object_name, location, etag)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Invalid XML provided for "CompleteMultipartUploadResult" '
                              'some fields are missing. Message: {0}'.format(error.message))

def parse_list_buckets(data):
    """
    Parser for list buckets response.

    :param data: Respone data for list buckets.
    :return: List of :class:`Bucket <Bucket>`.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListBucketsResult" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    bucket_list = []
    try:
        for buckets in root.findall('s3:Buckets', _S3_NS):
            for bucket in buckets:
                name = get_element_text(bucket, 's3:Name')
                creation_date = _iso8601_to_localized_time(get_element_text(bucket,
                                                                            's3:CreationDate'))
                bucket_list.append(Bucket(name, creation_date))
            return bucket_list
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Invalid XML provided for "ListBucketsResult" '
                              'some fields are missing. Message: {0}'.format(error.message))

def parse_list_objects(data, bucket_name):
    """
    Parser for list objects response.

    :param data: Response data for list objects.
    :param bucket_name: Response for the bucket.
    :return: Replies back three distinctive components.
       - List of :class:`Object <Object>`
       - True if list is truncated, False otherwise.
       - Object name marker for the next request.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListObjects" XML is not parsable. '
                              'Message: {0}'.format(error.message))
    is_truncated = False
    objects = []
    marker = None
    last_object_name = None
    for contents in root:
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}NextMarker':
            if contents.text is not None:
                marker = urldecode(contents.text)
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Contents':
            object_name = None
            last_modified = None
            etag = None
            size = 0
            for content in contents:
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}Key':
                    object_name = urldecode(content.text)
                    last_object_name = object_name
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}LastModified':
                    last_modified = _iso8601_to_localized_time(content.text)
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}ETag':
                    etag = content.text
                    if etag:
                        etag = etag.replace('"', '')
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}Size':
                    size = int(content.text)
            objects.append(Object(bucket_name, object_name, last_modified,
                                  etag, size, content_type=None))
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}CommonPrefixes':
            for content in contents:
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}Prefix':
                    object_name = urldecode(content.text)
                objects.append(Object(bucket_name,
                                      object_name, None, '', 0,
                                      content_type=None, is_dir=True))

    if is_truncated and marker is None:
        marker = last_object_name

    return objects, is_truncated, marker


def parse_list_multipart_uploads(data, bucket_name):
    """
    Parser for list multipart uploads response.

    :param data: Response data for list multipart uploads.
    :param bucket_name: Response for the bucket.
    :return: Replies back four distinctive components.
       - List of :class:`IncompleteUpload <IncompleteUpload>`
       - True if list is truncated, False otherwise.
       - Object name marker for the next request.
       - Upload id marker for the next request.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListMultipartUploads" XML is not parsable. '
                              'Message: {0}'.format(error.message))
    is_truncated = False
    uploads = []
    key_marker = None
    upload_id_marker = None
    for contents in root:
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}NextKeyMarker':
            if contents.text is not None:
                key_marker = urldecode(contents.text)
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}NextUploadIdMarker':
            upload_id_marker = contents.text
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Upload':
            object_name = None
            upload_id = None
            initiated = None
            for content in contents:
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}Key':
                    object_name = urldecode(content.text)
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}UploadId':
                    upload_id = content.text
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}Initiated':
                    initiated = _iso8601_to_localized_time(content.text)
            uploads.append(IncompleteUpload(bucket_name,
                                            object_name,
                                            upload_id,
                                            initiated))
    return uploads, is_truncated, key_marker, upload_id_marker


def parse_list_parts(data, bucket_name, object_name, upload_id):
    """
    Parser for list parts response.

    :param data: Response data for list parts.
    :param bucket_name: Response for the bucket.
    :param object_name: Response for the object.
    :param upload_id: Upload id of object name for
       the active multipart session.
    :return: Replies back three distinctive components.
       - List of :class:`UploadPart <UploadPart>`.
       - True if list is truncated, False otherwise.
       - Next part marker for the next request if the
         list was truncated.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListParts" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    is_truncated = False
    parts = []
    part_marker = None
    for contents in root:
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == \
           '{http://s3.amazonaws.com/doc/2006-03-01/}NextPartNumberMarker':
            part_marker = contents.text
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Part':
            etag = None
            size = None
            part_number = None
            last_modified = None
            for content in contents:
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}PartNumber':
                    part_number = int(content.text)
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}ETag':
                    etag = content.text
                    etag = etag.replace('"', '')
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}LastModified':
                    last_modified = _iso8601_to_localized_time(content.text)
                if content.tag == \
                   '{http://s3.amazonaws.com/doc/2006-03-01/}Size':
                    size = int(content.text)
            part = UploadPart(bucket_name, object_name,
                              upload_id, part_number,
                              etag, last_modified, size)
            parts.append(part)

    return parts, is_truncated, part_marker


def parse_new_multipart_upload(data):
    """
    Parser for new multipart upload response.

    :param data: Response data for new multipart upload.
    :return: Returns a upload id.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"NewMultipartUpload" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    try:
        upload_id = get_element_text(root, 's3:UploadId')
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Missing "UploadId" XML attribute from "NewMultipartUpload". '
                              'Message: {0}'.format(error.message))
    return upload_id

def parse_location_constraint(data):
    """
    Parser for location constraint response.

    :param data: Response data for get bucket location.
    :return: Returns location of your bucket.
    """
    try:
        bucket_location = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"BucketLocationConstraint" XML is not parsable.'
                              ' Message: {0}'.format(error.message))

    try:
        location_constraint = bucket_location.text
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Missing "LocationConstraint" XML attribute from '
                              '"BucketLocationConstraint". Message: {0}'.format(error.message))

    return location_constraint

def _iso8601_to_localized_time(date_string):
    """
    Convert iso8601 date string into UTC time.

    :param date_string: iso8601 formatted date string.
    :return: :class:`datetime.datetime`
    """
    parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    localized_time = pytz.utc.localize(parsed_date)
    return localized_time
