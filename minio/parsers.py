from xml.etree import ElementTree
from datetime import datetime

import pytz

from .acl import Acl

__author__ = 'minio'


def parse_list_buckets(data):
    root = ElementTree.fromstring(data)
    bucket_list = []
    for buckets in root.findall('{http://doc.s3.amazonaws.com/2006-03-01}Buckets'):
        for bucket in buckets:
            name = None
            creation_date = None
            for attribute in bucket:
                if attribute.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Name':
                    name = attribute.text
                if attribute.tag == '{http://doc.s3.amazonaws.com/2006-03-01}CreationDate':
                    creation_date = datetime.strptime(attribute.text, '%Y-%m-%dT%H:%M:%S.%fZ')
                    creation_date = pytz.utc.localize(creation_date)
            bucket_list.append(Bucket(name, creation_date))
    return bucket_list


def parse_acl(data):
    root = ElementTree.fromstring(data)

    public_read = False
    public_write = False
    authenticated_read = False
    authenticated_write = False

    for acls in root:
        if acls.tag == '{http://s3.amazonaws.com/doc/2006-03-01}AccessControlList':
            for grant in acls:
                user_uri = None
                permission = None
                for grant_property in grant:
                    if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01}Grantee':
                        for grantee in grant_property:
                            if grantee.tag == '{http://s3.amazonaws.com/doc/2006-03-01}URI':
                                user_uri = grantee.text
                    if grant_property.tag == '{http://s3.amazonaws.com/doc/2006-03-01}Permission':
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
        return Acl.authenticated()
    return Acl.private()


def parse_list_objects(data, bucket):
    root = ElementTree.fromstring(data)

    is_truncated = False
    objects = []
    marker = None
    for contents in root:
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}NextMarker':
            marker = contents.text
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Contents':
            key = None
            last_modified = None
            etag = None
            size = None
            for content in contents:
                if content.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Key':
                    key = content.text
                if content.tag == '{http://doc.s3.amazonaws.com/2006-03-01}LastModified':
                    last_modified = content.text
                if content.tag == '{http://doc.s3.amazonaws.com/2006-03-01}ETag':
                    etag = content.text
                if content.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Size':
                    size = content.text
            objects.append(Object(bucket, key, last_modified, etag, size))

    return objects, is_truncated, marker

def parse_incomplete_uploads(data, bucket):
    root = ElementTree.fromstring(data)

    is_truncated = False
    uploads = []
    key_marker = None
    upload_id_marker = None
    for contents in root:
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}IsTruncated':
            is_truncated = contents.text.lower() == 'true'
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}NextKeyMarker':
            key_marker = contents.text
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}NextUploadIdMarker':
            upload_id_marker = contents.text
        if contents.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Upload':
            key = None
            upload_id = None
            for content in contents:
                if content.tag == '{http://doc.s3.amazonaws.com/2006-03-01}Key':
                    key = content.text
                if content.tag == '{http://doc.s3.amazonaws.com/2006-03-01}UploadId':
                    upload_id = content.text
            uploads.append(IncompleteUpload(bucket, key, upload_id))

    return uploads, is_truncated, key_marker, upload_id_marker


def parse_error(response):
    if response.content is None:
        # TODO handle redirect
        # TODO handle 404
        pass

    code = None
    message = None
    request_id = None
    host_id = None
    resource = None

    root = ElementTree.fromstring(response.content)
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

    raise ResponseError(code, message, request_id, host_id, resource)


class ResponseError(BaseException):
    def __init__(self, code, message, request_id, host_id, resource):
        self.code = code
        self.message = message
        self.request_id = request_id
        self.host_id = host_id
        self.resource = resource


class Bucket(object):
    def __init__(self, name, created):
        self.name = name
        self.creation_date = created


class Object(object):
    def __init__(self, bucket, key, last_modified, etag, size, content_type=None):
        # TODO parse last_modified
        self.bucket = bucket
        self.key = key
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.content_type = content_type

class IncompleteUpload(object):
    def __init__(self, bucket, key, upload_id):
        self.bucket = bucket
        self.key = key
        self.upload_id = upload_id
