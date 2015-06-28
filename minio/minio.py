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

import hashlib
import platform
from urlparse import urlparse

import requests

from .generators import ListObjectsIterator, ListIncompleteUploads, ListUploadParts
from .helpers import get_target_url
from .parsers import parse_list_buckets, parse_acl, parse_error, Object
from .region import get_region
from .signer import sign_v4
from .xml_requests import bucket_constraint, generate_complete_multipart_upload

__author__ = 'minio'


class Minio:
    def __init__(self, url, access_key=None, secret_key=None):
        if not isinstance(url, basestring):
            raise TypeError(url)
        url_components = urlparse(url)

        if url_components.scheme is '':
            raise ValueError('url')

        if url_components.netloc is '':
            raise ValueError('url')

        self._scheme = url_components.scheme
        self._location = url_components.netloc
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = 'minio-py/' + '0.0.1' + ' (' + platform.system() + '; ' + platform.machine() + ')'

    # Client level
    def add_user_agent(self, name, version, parameters):
        if not isinstance(name, basestring):
            raise TypeError('name')
        name = name.strip()
        if name == '':
            raise ValueError('name')

        if not isinstance(version, basestring):
            raise TypeError('version')
        version = version.strip()
        if version == '':
            raise ValueError('version')

        for parameter in parameters:
            if parameter == '':
                raise ValueError('parameters')

        joined_parameters = '; '.join(parameters)
        components = [' ', name, '/', version, ' (', joined_parameters, ')']
        self._user_agent += ''.join(components)

    # Bucket level
    # noinspection PyUnusedLocal
    def make_bucket(self, bucket, acl=None):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'PUT'
        url = get_target_url(self._scheme, self._location, bucket=bucket)
        headers = {}

        region = get_region(self._location)

        content = ''
        if region is not 'us-east-1':
            content = bucket_constraint(region)
            headers['Content-Length'] = str(len(content))

        content_sha256 = get_sha256(content)

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=content_sha256)

        response = requests.put(url, data=content, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def list_buckets(self):
        url = get_target_url(self._scheme, self._location)
        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)

        return parse_list_buckets(response.content)

    def bucket_exists(self, bucket):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'HEAD'
        url = get_target_url(self._scheme, self._location, bucket=bucket)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.head(url, headers=headers)

        if response.status_code == 200:
            return True

        return False

    def remove_bucket(self, bucket):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'DELETE'
        url = get_target_url(self._scheme, self._location, bucket=bucket)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.delete(url, headers=headers)

        if response.status_code != 204:
            parse_error(response)

    def get_bucket_acl(self, bucket):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'GET'
        url = get_target_url(self._scheme, self._location, bucket=bucket, query={"acl": None})
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        return parse_acl(response.content)

    def set_bucket_acl(self, bucket, acl):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError
        method = 'PUT'
        url = get_target_url(self._scheme, self._location, bucket=bucket, query={"acl": None})
        headers = {
            'x-amz-acl': acl
        }

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.put(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def drop_all_incomplete_uploads(self, bucket):
        # check bucket
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError('bucket')

        uploads = ListIncompleteUploads(self._scheme, self._location, bucket, None, access_key=self._access_key,
                                        secret_key=self._secret_key)

        for upload in uploads:
            self._drop_incomplete_upload(bucket, upload.key, upload.upload_id)

    # Object Level
    def get_object(self, bucket, key):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        if not isinstance(key, basestring):
            raise TypeError('key')
        key = key.strip()
        if key == '':
            raise ValueError

        method = 'GET'
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers, stream=True)

        if response.status_code != 200:
            parse_error(response)

        return response.iter_content()

    def put_object(self, bucket, key, length, data, content_type="application/octet-stream"):
        # check bucket
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError('bucket')

        # check key
        if not isinstance(key, basestring):
            raise TypeError('key')
        key = key.strip()
        if key == '':
            raise ValueError('key')

        # check length
        if not isinstance(length, int):
            raise TypeError('length')
        if length <= 0:
            raise ValueError('length')

        # check content_type
        if not isinstance(content_type, basestring):
            raise TypeError('content_type')
            # TODO implement this feature

        content_type = content_type.strip()
        if content_type == '':
            raise ValueError('content_type')

        if length <= 5 * 1024 * 1024:
            return self._do_put_object(bucket, key, length, data, content_type)
        self._stream_put_object(bucket, key, length, data, content_type)

    def list_objects(self, bucket, prefix=None, recursive=True):
        return ListObjectsIterator(self._scheme, self._location, bucket, prefix, recursive, self._access_key,
                                   self._secret_key)

    def stat_object(self, bucket, key):
        # check bucket
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError('bucket')

        # check key
        if not isinstance(key, basestring):
            raise TypeError('key')
        key = key.strip()
        if key == '':
            raise ValueError('key')

        method = 'HEAD'
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.head(url, headers=headers, stream=True)

        if response.status_code != 200:
            parse_error(response)

        content_type = response.headers['Content-Type']
        etag = response.headers['ETag']
        size = response.headers['Content-Length']
        last_modified = response.headers['Last-Modified']

        return Object(bucket, key, content_type=content_type, last_modified=last_modified, etag=etag, size=size)

    def remove_object(self, bucket, key):
        # check bucket
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError('bucket')

        # check key
        if not isinstance(key, basestring):
            raise TypeError('key')
        key = key.strip()
        if key == '':
            raise ValueError('key')

        method = 'DELETE'
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.delete(url, headers=headers, stream=True)

        if response.status_code != 204:
            parse_error(response)

    def drop_incomplete_upload(self, bucket, key):
        # check bucket
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError('bucket')

        # check key
        if not isinstance(key, basestring):
            raise TypeError('key')
        key = key.strip()
        if key == '':
            raise ValueError('key')
        uploads = ListIncompleteUploads(self._scheme, self._location, bucket, key, access_key=self._access_key,
                                        secret_key=self._secret_key)
        for upload in uploads:
            self._drop_incomplete_upload(bucket, upload.key, upload.upload_id)

    # helper functions

    def _do_put_object(self, bucket, key, length, data, content_type='application/octet-stream',
                       upload_id=None, part_id=None):
        method = 'PUT'

        # guard against inconsistent upload_id/part_id states
        if upload_id is None and part_id is not None:
            raise ValueError('part_id')
        if upload_id is not None and part_id is None:
            raise ValueError('upload_id')

        if upload_id is not None and part_id is not None:
            url = get_target_url(self._scheme, self._location, bucket=bucket, key=key,
                                 query={'uploadId': upload_id, 'partId': part_id})
        else:
            url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)

        content_sha256 = get_sha256(data)

        headers = {
            'Content-Length': length,
            'Content-Type': content_type
        }

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=content_sha256)

        response = requests.put(url, headers=headers, data=data)

        if response.status_code != 200:
            parse_error(response)

    def _stream_put_object(self, bucket, key, length, data, content_type):
        part_size = 5 * 1024 * 1024

        current_uploads = ListIncompleteUploads(self._scheme, self._location, bucket, key, access_key=self._access_key,
                                                secret_key=self._secret_key)

        upload_id = None
        for upload in current_uploads:
            upload_id = upload.upload_id
        uploaded_parts = {}
        if upload_id is not None:
            part_iter = ListUploadParts(self._scheme, self._location, bucket, key, upload_id,
                                        access_key=self._access_key, secret_key=self._secret_key)
            for part in part_iter:
                uploaded_parts[part.part_number] = part
        else:
            upload_id = self._new_multipart_upload(bucket, key)
        total_uploaded = 0
        current_part_number = 1
        etags = []
        while total_uploaded < length:
            current_data = [0x01, 0x02]
            current_data_sha256 = get_sha256(current_data)
            previously_uploaded_part = uploaded_parts[current_part_number]
            if previously_uploaded_part is None or previously_uploaded_part.etag != current_data_sha256:
                etag = self._do_put_object(bucket=bucket, key=key, length=length, data=current_data,
                                           content_type=content_type, upload_id=upload_id, part_id=current_part_number)
            else:
                etag = previously_uploaded_part.etag
            etags.append(etag)
            total_uploaded += part_size
            current_part_number += 1
        self._complete_multipart_upload(bucket, key, upload_id, etags)

    def _drop_incomplete_upload(self, bucket, key, upload_id):
        method = 'DELETE'
        query = {
            'uploadId': upload_id
        }
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key, query=query)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.delete(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def _new_multipart_upload(self, bucket, key):
        method = 'PUT'
        query = {
            'uploads': None
        }
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key, query=query)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.put(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)
        return response.content.decode('utf-8')

    def _complete_multipart_upload(self, bucket, key, upload_id, etags):
        method = 'PUT'
        query = {
            'uploads': None,
            'uploadId': upload_id
        }
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key, query=query)
        headers = {}

        data = generate_complete_multipart_upload(etags)
        data_sha256 = get_sha256(data)

        headers['Content-Length'] = len(data)
        headers['Content-Type'] = 'application/xml'

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=data_sha256)

        response = requests.put(url, headers=headers, data=data)

        if response.status_code != 200:
            parse_error(response)


def get_sha256(content):
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.digest()
