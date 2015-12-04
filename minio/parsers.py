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
"""

import pytz

from xml.etree import cElementTree
from xml.etree.cElementTree import ParseError
from datetime import datetime

from .error import ResponseError, InvalidXMLError
from .bucket_acl import Acl
from .compat import urldecode
from .definitions import (Object, Bucket, IncompleteUpload, UploadPart)

def parse_list_buckets(data):
    """
    Parser for list buckets response.

    :param data: Respone data for list buckets.
    :return: List of :class:`Bucket <Bucket>`.
    """
    try:
        root = cElementTree.fromstring(data)
    except Exception as e:
        raise InvalidXMLError('"ListBucketsResult" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))

    for buckets in root:
        if buckets.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Owner':
            continue
        if buckets.tag != '{http://s3.amazonaws.com/doc/2006-03-01/}Buckets':
            raise InvalidXMLError('Missing "Buckets" XML attribute.')
        for bucket in buckets:
            name = None
            creation_date = None
            for attribute in bucket:
                if attribute.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Name':
                    name = attribute.text
                    continue
                if attribute.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}CreationDate':
                    creation_date = _iso8601_to_localized_time(attribute.text)
            yield Bucket(name, creation_date)

def parse_acl(data):
    """
    Parser for access control list response.

    :param data: Response data of access control list for a bucket.
    :return: :class:`Acl <Acl>`
    """
    try:
        root = cElementTree.fromstring(data)
    except Exception as e:
        raise InvalidXMLError('"AccessControlList" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))

    public_read = False
    public_write = False

    for acls in root:
        if acls.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Owner':
            continue
        if acls.tag != '{http://s3.amazonaws.com/doc/2006-03-01/}AccessControlList':
            raise InvalidXMLError('Missing "AccessControlList" XML attribute.')
        for grant in acls:
            user_uri = None
            permission = None
            for grant_property in grant:
                if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Grantee':
                    for grantee in grant_property:
                        if grantee.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}URI':
                            user_uri = grantee.text
                            break
                    continue
                if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Permission':
                    permission = grant_property.text
                    break
            if user_uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                if permission == 'READ':
                    return Acl.authenticated_read()
            if user_uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission == 'WRITE':
                public_write = True
            if user_uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission == 'READ':
                public_read = True
    if public_read is True and public_write is True:
        return Acl.public_read_write()
    if public_read is True and public_write is False:
        return Acl.public_read()
    return Acl.private()

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
    except Exception as e:
        raise InvalidXMLError('"ListObjects" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))
    is_truncated = False
    objects = []
    marker = None
    last_object_name = None
    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextMarker':
            if contents.text is not None:
                marker = urldecode(contents.text)
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Contents':
            object_name = None
            last_modified = None
            etag = None
            size = 0
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Key':
                    object_name = urldecode(content.text)
                    last_object_name = object_name
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}LastModified':
                    last_modified = _iso8601_to_localized_time(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}ETag':
                    etag = content.text
                    etag = etag.replace('"', '')
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Size':
                    size = int(content.text)
            objects.append(Object(bucket_name, object_name, last_modified, etag, size, content_type=None))
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}CommonPrefixes':
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Prefix':
                    object_name = urldecode(content.text)
                objects.append(Object(bucket_name, object_name, None, '', 0, content_type=None, is_dir=True))

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
    except Exception as e:
        raise InvalidXMLError('"ListMultipartUploads" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))
    is_truncated = False
    uploads = []
    key_marker = None
    upload_id_marker = None
    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextKeyMarker':
            if contents.text is not None:
                key_marker = urldecode(contents.text)
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextUploadIdMarker':
            upload_id_marker = contents.text
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Upload':
            object_name = None
            upload_id = None
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Key':
                    object_name = urldecode(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}UploadId':
                    upload_id = content.text
            uploads.append(IncompleteUpload(bucket_name, object_name, upload_id))
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
       - Next part marker for the next request if the list was truncated.
    """
    try:
        root = cElementTree.fromstring(data)
    except Exception as e:
        raise InvalidXMLError('"ListParts" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))
    is_truncated = False
    parts = []
    part_marker = None
    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextPartNumberMarker':
            part_marker = contents.text
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Part':
            part_number = None
            etag = None
            last_modified = None
            size = None
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}PartNumber':
                    part_number = int(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}ETag':
                    etag = content.text
                    etag = etag.replace('"', '')
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}LastModified':
                    last_modified = _iso8601_to_localized_time(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Size':
                    size = int(content.text)
            parts.append(UploadPart(bucket_name, object_name, upload_id, part_number, etag,
                                    last_modified, size))
    return parts, is_truncated, part_marker

def parse_new_multipart_upload(data):
    """
    Parser for new multipart upload response.

    :param data: Response data for new multipart upload.
    :return: Returns a upload id.
    """
    try:
        root = cElementTree.fromstring(data)
    except Exception as e:
        raise InvalidXMLError('"NewMultipartUpload" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))

    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}UploadId':
            return contents.text

    raise InvalidXMLError('Missing "UploadId" XML attribute.')

def parse_location_constraint(data):
    """
    Parser for location constraint response.

    :param data: Response data for get bucket location.
    :return: Returns location of your bucket.
    """
    try:
        content = cElementTree.fromstring(data)
    except Exception as e:
        raise InvalidXMLError('"BucketLocationConstraint" XML is not parsable. ' \
                              'Message: {0}'.format(e.message))

    if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}LocationConstraint':
        return content.text

    raise InvalidXMLError('Missing "LocationConstraint" XML attribute.')

def _iso8601_to_localized_time(date_string):
    """
    Convert iso8601 date string into UTC time.

    :param date_string: iso8601 formatted date string.
    :return: :class:`datetime.datetime`
    """
    parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    localized_time = pytz.utc.localize(parsed_date)
    return localized_time
