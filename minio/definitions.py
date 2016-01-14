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
minio.definitions
~~~~~~~~~~~~~~~

This module contains the primary objects that power Minio.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""


class Bucket(object):
    """
    A bucket metadata :class:`Bucket <Bucket>`.

    :param name: Bucket name.
    :param created: Bucket creation date.
    """
    def __init__(self, name, created):
        self.name = name
        self.creation_date = created

    def __str__(self):
        return '<Bucket: {0} {1}>'.format(self.name, self.creation_date)


class Object(object):
    """
    A object metadata :class:`Object <Object>`.

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param last_modified: Object when it was last modified on server.
    :param etag: ETag saved on server for the object_name.
    :param size: Size of the object on server.
    :param content_type: Optional parameter indicating content type.
    :param is_dir: Optional parameter differentiating object prefixes.
    """
    def __init__(self, bucket_name, object_name, last_modified, etag, size,
                 content_type=None, is_dir=False):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.content_type = content_type
        self.is_dir = is_dir

    def __str__(self):
        string_format = '<Object: bucket_name: {0} object_name: {1}' \
                        ' last_modified: {2} etag: {3} size: {4}' \
                        ' content_type: {5}, is_dir: {6}>'
        return string_format.format(self.bucket_name,
                                    self.object_name.encode('utf-8'),
                                    self.last_modified,
                                    self.etag, self.size,
                                    self.content_type,
                                    self.is_dir)


class MultipartUploadResult(object):
    """
    A completed multipart upload metadata
         :class:`MultipartUploadResult <MultipartUploadResult>`.

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param location: Object uploaded location.
    :param etag: Object final etag.
    """
    def __init__(self, bucket_name, object_name, location, etag):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.location = location
        self.etag = etag

    def __str__(self):
        string_format = ('<IncompleteUpload: bucket_name: {0}'
                         ' object_name: {1} location: {2} etag: {3}>')
        return string_format.format(self.bucket_name, self.object_name,
                                    self.location, self.etag)


class IncompleteUpload(object):
    """
    A partially uploaded object's metadata
         :class:`IncompleteUpload <IncompleteUpload>`.

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param upload_id: Partially uploaded object's upload id.
    :param initiated: Date when the multipart was initiated.
    """
    def __init__(self, bucket_name, object_name, upload_id, initiated):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.upload_id = upload_id
        self.initiated = initiated
        self.size = 0

    def __str__(self):
        string_format = ('<IncompleteUpload: bucket_name: {0}'
                         ' object_name: {1} upload_id: {2}'
                         ' initiated:{3} size: {4}>')
        return string_format.format(self.bucket_name, self.object_name,
                                    self.upload_id, self.initiated, self.size)


class UploadPart(object):
    """
    A multipart upload part metadata :class:`UploadPart <UploadPart>`

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param upload_id: Partially uploaded object's upload id.
    :param part_number: Part number of the part.
    :param etag: ETag of the part.
    :last_modified: Last modified time of the part.
    :size: Size of the part.
    """
    def __init__(self, bucket_name, object_name, upload_id, part_number, etag,
                 last_modified, size):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.upload_id = upload_id
        self.part_number = part_number
        self.etag = etag
        self.last_modified = last_modified
        self.size = size

    def __str__(self):
        string_format = '<UploadPart: bucket_name: {0} object_name: {1}' \
                        ' upload_id: {2} part_number: {3} etag: {4}' \
                        ' last_modified: {5} size: {6}>'
        return string_format.format(self.bucket_name,
                                    self.object_name,
                                    self.upload_id,
                                    self.part_number,
                                    self.etag,
                                    self.last_modified,
                                    self.size)
