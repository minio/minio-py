# -*- coding: utf-8 -*-
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

import pytz

from xml.etree import cElementTree
from datetime import datetime

from .acl import Acl
from ._compat import urlencode

def parse_list_buckets(data):
    root = cElementTree.fromstring(data)
    bucket_list = []
    for buckets in root:
        if buckets.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Buckets':
            for bucket in buckets:
                name = None
                creation_date = None
                for attribute in bucket:
                    if attribute.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Name':
                        name = attribute.text
                    if attribute.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}CreationDate':
                        creation_date = _parse_date(attribute.text)
                bucket_list.append(Bucket(name, creation_date))
    return bucket_list


def parse_acl(data):
    root = cElementTree.fromstring(data)

    public_read = False
    public_write = False
    authenticated_read = False
    authenticated_write = False

    for acls in root:
        if acls.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}AccessControlList':
            for grant in acls:
                user_uri = None
                permission = None
                for grant_property in grant:
                    if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Grantee':
                        for grantee in grant_property:
                            if grantee.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}URI':
                                user_uri = grantee.text
                    if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Permission':
                        permission = grant_property.text
                if user_uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission == 'WRITE':
                    public_write = True
                if user_uri == 'http://acs.amazonaws.com/groups/global/AllUsers' and permission == 'READ':
                    public_read = True
                if user_uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' and permission == 'READ':
                    authenticated_read = True
                if user_uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' and permission == 'WRITE':
                    authenticated_write = True

    if public_read is True and public_write is True:
        return Acl.public_read_write()
    if public_read is True and public_write is False:
        return Acl.public_read()
    if authenticated_read is True and authenticated_write is False:
        return Acl.authenticated_read()
    return Acl.private()


def parse_list_objects(data, bucket):
    root = cElementTree.fromstring(data)

    is_truncated = False
    objects = []
    marker = None
    last_key = None
    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextMarker':
            if contents.text is not None:
                marker = urlencode(contents.text)
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Contents':
            key = None
            last_modified = None
            etag = None
            size = None
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Key':
                    key = urlencode(content.text)
                    last_key = key
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}LastModified':
                    last_modified = _parse_date(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}ETag':
                    etag = content.text
                    etag = etag.replace('"', '')
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Size':
                    size = content.text
            objects.append(Object(bucket, key, last_modified, etag, size, content_type=None))
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}CommonPrefixes':
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Prefix':
                    key = urlencode(content.text)
                # noinspection PyUnboundLocalVariable
                objects.append(Object(bucket, key, None, '', 0, content_type=None, is_dir=True))

    if is_truncated and marker is None:
        marker = last_key

    return objects, is_truncated, marker


def parse_incomplete_uploads(data, bucket):
    root = cElementTree.fromstring(data)

    is_truncated = False
    uploads = []
    key_marker = None
    upload_id_marker = None
    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextKeyMarker':
            if contents.text is not None:
                key_marker = urlencode(contents.text)
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}NextUploadIdMarker':
            upload_id_marker = contents.text
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Upload':
            key = None
            upload_id = None
            for content in contents:
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Key':
                    key = urlencode(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}UploadId':
                    upload_id = content.text
            uploads.append(IncompleteUpload(bucket, key, upload_id))

    return uploads, is_truncated, key_marker, upload_id_marker


def parse_uploaded_parts(data, bucket, key, upload_id):
    root = cElementTree.fromstring(data)

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
                    last_modified = _parse_date(content.text)
                if content.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}Size':
                    size = content.text
            parts.append(UploadPart(bucket, key, upload_id, part_number, etag,
                                    last_modified, size))
    return parts, is_truncated, part_marker


def parse_new_multipart_upload(data):
    root = cElementTree.fromstring(data)

    upload_id = None

    for contents in root:
        if contents.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}UploadId':
            upload_id = contents.text

    return upload_id


def parse_error(response, resource=None):
    if len(response.data) == 0:
        amz_request_id = ''
        amz_host_id = ''
        if 'x-amz-request-id' in response.headers:
            amz_request_id = response.headers['x-amz-request-id']
        if 'x-amz-id-2' in response.headers:
            amz_host_id = response.headers['x-amz-id-2']
        if response.status == 405 or response.status == 501:
            raise ResponseError('MethodNotAllowedException', response.reason,
                                amz_request_id, amz_host_id, resource, None)
        if response.status == 404:
            raise ResponseError('ObjectNotFoundException', response.reason,
                                amz_request_id, amz_host_id, resource, None)
        if response.status == 403:
            raise ResponseError('AccessDeniedException', response.reason,
                                amz_request_id, amz_host_id, resource, None)
        if response.status == 400:
            raise ResponseError('BadRequestException', response.reason,
                                amz_request_id, amz_host_id, resource, None)
        if response.status == 301 or response.status == 307:
            raise ResponseError('Redirect', response.reason,
                                amz_request_id, amz_host_id, resource, None)
        raise ResponseError('UnknownException', response.reason,
                            amz_request_id, amz_host_id, resource, None)

    code = None
    message = None
    request_id = None
    host_id = None
    resource = None

    root = cElementTree.fromstring(response.data)
    for attribute in root:
        if attribute.tag == 'Code':
            code = attribute.text
        if attribute.tag == 'Message':
            message = attribute.text
        if attribute.tag == 'RequestId':
            request_id = attribute.text
        if attribute.tag == 'HostId':
            host_id = attribute.text
        if attribute.tag == 'Resource':
            resource = attribute.text

    raise ResponseError(code, message,
                        request_id, host_id, resource,
                        response.data)

class ResponseError(BaseException):
    def __init__(self, code, message, request_id, host_id, resource, xml=None):
        self.code = code
        self.message = message
        self.request_id = request_id
        self.host_id = host_id
        self.resource = resource
        self.xml = xml

    def __str__(self):
        return 'ResponseError: code: {0}, message: {1}, request_id: {2},'
        'host_id: {3}, resource: {4}, xml: {5}'.format(self.code, self.message,
                                                       self.request_id,
                                                       self.host_id,
                                                       self.resource, self.xml)


class Bucket(object):
    def __init__(self, name, created):
        self.name = name
        self.creation_date = created

    def __str__(self):
        return '<Bucket: {0} {1}>'.format(self.name, self.creation_date)


class Object(object):
    def __init__(self, bucket, key, last_modified, etag, size,
                 content_type=None, is_dir=False):
        self.bucket = bucket
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.content_type = content_type
        self.is_dir = is_dir

    def __str__(self):
        string_format = '<Object: bucket: {0} key: {1} last_modified: {2}' \
                        ' etag: {3} size: {4} content_type: {5}, is_dir: {6}>'
        return string_format.format(self.bucket, self.key, self.last_modified,
                                    self.etag, self.size, self.content_type,
                                    self.is_dir)

class IncompleteUpload(object):
    def __init__(self, bucket, key, upload_id):
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id

    def __str__(self):
        return '<IncompleteUpload: {0} {1} {2}>'.format(self.bucket, self.key,
                                                        self.upload_id)

class UploadPart(object):
    def __init__(self, bucket, key, upload_id, part_number, etag,
                 last_modified, size):
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id
        self.part_number = part_number
        self.etag = etag
        self.last_modified = last_modified
        self.size = size

def _parse_date(date_string):
    parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    localized_time = pytz.utc.localize(parsed_date)
    return localized_time
