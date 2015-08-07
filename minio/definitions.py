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
        string_format = '<IncompleteUpload: bucket: {0} key: {1}' \
                        ' upload_id: {2}>'
        return string_format.format(self.bucket, self.key, self.upload_id)

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

    def __str__(self):
        string_format = '<UploadPart: bucket: {0} key: {1} upload_id: {2}' \
                        ' part_number: {3} etag: {4} last_modified: {5}' \
                        ' size: {6}>'
        return string_format.format(self.bucket,
                                    self.key,
                                    self.upload_id,
                                    self.part_number,
                                    self.etag,
                                    self.last_modified,
                                    self.size)
