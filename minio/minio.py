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

from io import RawIOBase
import io
import platform

try:
    import urllib.parse as compat_urlparse
except ImportError: # Python 2
    import urlparse as compat_urlparse

import requests

from .generators import ListObjectsIterator, ListIncompleteUploads, ListUploadParts
from .helpers import get_target_url, is_non_empty_string, is_positive_int, get_sha256, convert_binary_to_base64, \
    get_md5, calculate_part_size, convert_binary_to_hex
from .parsers import parse_list_buckets, parse_acl, parse_error, Object, parse_new_multipart_upload
from .region import get_region
from .signer import sign_v4
from .xml_requests import bucket_constraint, generate_complete_multipart_upload

__author__ = 'minio'


class Minio:
    def __init__(self, url, access_key=None, secret_key=None):
        """
        Creates a new object storage client.

        Examples:

            client = Minio('http://localhost:9000', 'ACCESS_KEY', 'SECRET_KEY')
            client = Minio('http://s3-us-west-2.amazonaws.com:9000', 'ACCESS_KEY', 'SECRET_KEY')

        :param url: A string of the URL of the object storage server.
        :param access_key: Access key to sign requests with.
        :param secret_key: Secret key to sign requests with.
        :return: Minio object
        """
        is_non_empty_string('url', url)

        url_components = compat_urlparse(url)

        is_non_empty_string('url scheme', url_components.scheme)

        is_non_empty_string('url location', url_components.netloc)

        self._scheme = url_components.scheme
        self._location = url_components.netloc
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = 'minio-py/' + '0.0.1' + ' (' + platform.system() + '; ' + platform.machine() + ')'

    # Client level
    def add_user_agent(self, name, version, parameters):
        """
        Adds an entry to the list of user agents.

        Example:
            minio.add_user_agent('my_app', '1.0.0', ['ex', 'parrot'])
            # Results in my_app/1.0.0 (ex; parrot) appended to user agent

        :param name: user agent name
        :param version: user agent version
        :param parameters: list of string parameters to include in parameters section
        :return: None
        """
        is_non_empty_string('name', name)
        is_non_empty_string('version', version)

        for parameter in parameters:
            is_non_empty_string('parameters', parameter)

        joined_parameters = '; '.join(parameters)
        components = [' ', name, '/', version, ' (', joined_parameters, ')']
        self._user_agent += ''.join(components)

    # Bucket level
    # noinspection PyUnusedLocal
    def make_bucket(self, bucket, acl=None):
        """
        Make a new bucket on the server.

        Optionally include an ACL. Valid ACLs are as follows:

            Acl.public_read_write()
            Acl.public_read()
            Acl.authenticated_read()
            Acl.private()

        Examples:
            minio.make_bucket('foo')
            minio.make_bucket('foo', Acl.public_read())

        :param bucket: Bucket to create on server
        :param acl: Canned ACL to use. Default is Acl.private()
        :return:
        """
        is_non_empty_string('bucket', bucket)

        method = 'PUT'
        url = get_target_url(self._scheme, self._location, bucket=bucket)
        headers = {}

        region = get_region(self._location)

        content = ''
        if region is not 'us-east-1':
            content = bucket_constraint(region)
            headers['Content-Length'] = str(len(content))

        content_sha256 = get_sha256(content)
        content_md5 = convert_binary_to_base64(get_md5(content))
        headers['Content-MD5'] = content_md5

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=content_sha256)

        response = requests.put(url, data=content, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def list_buckets(self):
        """
        List all buckets owned by the user.


        Example:
            bucket_list = minio.list_buckets()j
            for bucket in bucket_list:
                print bucket.name
                print bucket.created_date

        :return: A list of buckets owned by the current user.
        """
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
        """
        Check if the bucket exists and if the user has access to it.

        :param bucket: A bucket to test the existence and access of.
        :return: True if the bucket exists and the user has access. Otherwise, returns False
        """
        is_non_empty_string('bucket', bucket)

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
        """
        Remove a bucket.

        :param bucket: Bucket to remove
        :return: None
        """
        is_non_empty_string('bucket', bucket)

        method = 'DELETE'
        url = get_target_url(self._scheme, self._location, bucket=bucket)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.delete(url, headers=headers)

        if response.status_code != 204:
            parse_error(response)

    def get_bucket_acl(self, bucket):
        """
        Get a bucket's canned ACL, if any.

        Example:
            canned_acl = minio.get_bucket_acl('foo')
            if canned_acl == Acl.private():
                # do something

        :param bucket: Bucket to check canned ACL of.
        :return: A string representing the currently used canned ACL if one is set.
        """
        is_non_empty_string('bucket', bucket)

        method = 'GET'
        url = get_target_url(self._scheme, self._location, bucket=bucket, query={"acl": None})
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        return parse_acl(response.content)

    def set_bucket_acl(self, bucket, acl):
        """
        Set a bucket's canned acl

        Valid ACLs include:
            Acl.public_read_write()
            Acl.public_read()
            Acl.authenticated_read()
            Acl.private()

        Example:
            canned_acl = minio.get_bucket_acl('foo')
            if canned_acl == Acl.private():
                # do something

        :param bucket: Bucket to set
        :param acl: ACL to set
        :return: None
        """
        is_non_empty_string('bucket', bucket)

        method = 'PUT'
        url = get_target_url(self._scheme, self._location, bucket=bucket, query={"acl": None})

        md5_sum = convert_binary_to_base64(get_md5(''))

        headers = {
            'x-amz-acl': acl,
            'Content-MD5': md5_sum
        }

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.put(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def drop_all_incomplete_uploads(self, bucket):
        """
        Drop all incomplete uploads in a bucket.

        :param bucket: Bucket to drop all incomplete uploads.
        :return: None
        """
        # check bucket
        is_non_empty_string('bucket', bucket)

        uploads = ListIncompleteUploads(self._scheme, self._location, bucket, None, access_key=self._access_key,
                                        secret_key=self._secret_key)

        for upload in uploads:
            self._drop_incomplete_upload(bucket, upload.key, upload.upload_id)

    # Object Level
    def get_object(self, bucket, key, offset=None, length=None):
        """
        Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        Examples:
            my_object = minio.get_object('foo', 'bar')
            my_partial_object = minio.get_object('foo', 'bar', 2, 4)

        :param bucket: Bucket to retrieve object from
        :param key: Key to retrieve
        :param offset: Optional offset to retrieve bytes from. Must be >= 0
        :param length: Optional number of bytes to retrieve. Must be > 0
        :return: An iterable containing a byte stream of the data.
        """
        is_non_empty_string('bucket', bucket)
        is_non_empty_string('key', key)
        if offset is not None:
            is_positive_int('offset', offset, True)
        if length is not None:
            is_positive_int('length', length)

        request_range = None
        if offset is not None and length is not None:
            request_range = str(offset) + "-" + str(offset + length - 1)
        if offset is not None and length is None:
            request_range = str(offset) + "-"
        if offset is None and length is not None:
            request_range = "-" + str(length - 1)

        method = 'GET'
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)
        headers = {}

        if request_range is not None:
            headers['Range'] = 'bytes=' + request_range

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers, stream=True)

        if not (response.status_code == 200 or response.status_code == 206):
            parse_error(response)

        return response.iter_content()

    def put_object(self, bucket, key, length, data, content_type="application/octet-stream"):
        """
        Add a new object to the object storage server.

        Data can either be a string, byte array, or reader (e.g. open('foo'))

        Examples:
            minio.put('foo', 'bar', 11, 'hello world')

            minio.put('foo', 'bar', 11, b'hello world', 'text/plain')

            with open('hello.txt', 'rb') as data:
                minio.put('foo', 'bar', 11, b'hello world', 'text/plain')

        :param bucket: Bucket of new object.
        :param key: Key of new object.
        :param length: Total length of object. Used to ensure complete upload and calculate upload part size.
        :param data: Contents to upload.
        :param content_type: mime type of object as a string.
        :return: None
        """
        is_non_empty_string('bucket', bucket)
        is_non_empty_string('key', key)
        is_positive_int('length', length)

        # check content_type
        if not isinstance(content_type, basestring):
            raise TypeError('content_type')
            # TODO implement this feature

        content_type = content_type.strip()
        if content_type == '':
            raise ValueError('content_type')

        if isinstance(data, basestring):
            data = data.encode('utf-8')

        if length <= 5 * 1024 * 1024:
            # we reference 'file' for python 2.7 compatibility, RawIOBase for 3.X
            if type(data).__name__ == 'file' or isinstance(data, io.BufferedReader):
                data = data.read(length)
            return self._do_put_object(bucket, key, length, data, content_type)
        self._stream_put_object(bucket, key, length, data, content_type)

    def list_objects(self, bucket, prefix=None, recursive=True):
        """
        List objects in the given bucket.


        Objects may be filtered by a given prefix, delimited without recursion, or both.

        Examples:
            objects = minio.list_objects('foo')
            for current_object in objects:
                print current_object
            # hello
            # hello/world/1
            # hello/world/2
            # world/wide/web

            objects = minio.list_objects('foo', prefix='hello/')
            for current_object in objects:
                print current_object
            # hello/world/1
            # hello/world/2

            objects = minio.list_objects('foo', recursive=False)
            for current_object in objects:
                print current_object
            # hello/
            # world/

            objects = minio.list_objects('foo', prefix='hello/', recursive=False)
            for current_object in objects:
                print current_object
            # hello/world/

        :param bucket: Bucket to list objects from
        :param prefix: String specifying what all objects returned must begin with
        :param recursive: Boolean specifying whether to return as flat namespace or delimited by '/'
        :return: An iterator of objects in alphabetical order.
        """
        is_non_empty_string('bucket', bucket)
        return ListObjectsIterator(self._scheme, self._location, bucket, prefix, recursive, self._access_key,
                                   self._secret_key)

    def stat_object(self, bucket, key):
        """
        Check if an object exists.

        :param bucket: Bucket of object.
        :param key: Key of object
        :return: True if object exists and the user has access.
        """
        is_non_empty_string('bucket', bucket)
        is_non_empty_string('key', key)

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
        """
        Remove an object from the bucket.

        :param bucket: Bucket of object to remove
        :param key: Key of object to remove
        :return: None
        """
        is_non_empty_string('bucket', bucket)
        is_non_empty_string('key', key)

        method = 'DELETE'
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.delete(url, headers=headers, stream=True)

        if response.status_code != 204:
            parse_error(response)

    def drop_incomplete_upload(self, bucket, key):
        """
        Drops all in complete uploads for a given bucket and key.

        :param bucket: Bucket to drop incomplete uploads
        :param key: Key of object to drop incomplete uploads of
        :return: None
        """
        is_non_empty_string('bucket', bucket)
        is_non_empty_string('key', key)

        # check key
        uploads = ListIncompleteUploads(self._scheme, self._location, bucket, key, access_key=self._access_key,
                                        secret_key=self._secret_key)
        for upload in uploads:
            self._drop_incomplete_upload(bucket, upload.key, upload.upload_id)

    # helper functions

    def _do_put_object(self, bucket, key, length, data, content_type='application/octet-stream',
                       upload_id=None, part_number=None):
        method = 'PUT'

        # guard against inconsistent upload_id/part_id states
        if upload_id is None and part_number is not None:
            raise ValueError('part_id')
        if upload_id is not None and part_number is None:
            raise ValueError('upload_id')

        if upload_id is not None and part_number is not None:
            url = get_target_url(self._scheme, self._location, bucket=bucket, key=key,
                                 query={'uploadId': upload_id, 'partNumber': part_number})
        else:
            url = get_target_url(self._scheme, self._location, bucket=bucket, key=key)

        content_sha256 = get_sha256(data)
        content_md5 = convert_binary_to_base64(get_md5(data))

        headers = {
            'Content-Length': length,
            'Content-Type': content_type,
            'Content-MD5': content_md5
        }

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=content_sha256)

        response = requests.put(url, headers=headers, data=data)

        if response.status_code != 200:
            parse_error(response)

        return response.headers['ETag']

    def _stream_put_object(self, bucket, key, length, data, content_type):
        if type(data).__name__ != 'file':
            if not isinstance(data, io.BufferedReader):
                if not isinstance(data, RawIOBase):
                    data = io.BytesIO(data)
                data = io.BufferedReader(data)

        part_size = calculate_part_size(length)

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
            current_data = data.read(part_size)
            if len(current_data) == 0:
                break
            current_data_md5 = convert_binary_to_hex(get_md5(current_data))
            previously_uploaded_part = None
            if current_part_number in uploaded_parts:
                previously_uploaded_part = uploaded_parts[current_part_number]
            if previously_uploaded_part is None or previously_uploaded_part.etag != current_data_md5:
                etag = self._do_put_object(bucket=bucket, key=key, length=len(current_data), data=current_data,
                                           content_type=content_type, upload_id=upload_id,
                                           part_number=current_part_number)
            else:
                etag = previously_uploaded_part.etag
            etags.append(etag)
            total_uploaded += len(current_data)
            current_part_number += 1
        if total_uploaded != length:
            raise ValueError('len(data) does not match length')
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

        if response.status_code != 204:
            parse_error(response)

    def _new_multipart_upload(self, bucket, key):
        method = 'POST'
        query = {
            'uploads': None
        }
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key, query=query)

        md5_sum = convert_binary_to_base64(get_md5(b''))
        headers = {
            'Content-MD5': md5_sum
        }

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.post(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)
        return parse_new_multipart_upload(response.content)

    def _complete_multipart_upload(self, bucket, key, upload_id, etags):
        method = 'POST'
        query = {
            'uploadId': upload_id
        }
        url = get_target_url(self._scheme, self._location, bucket=bucket, key=key, query=query)
        headers = {}

        data = generate_complete_multipart_upload(etags)
        data_sha256 = get_sha256(data)
        data_md5 = convert_binary_to_base64(get_md5(data))

        headers['Content-Length'] = len(data)
        headers['Content-Type'] = 'application/xml'
        headers['Content-MD5'] = data_md5

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=data_sha256)

        response = requests.post(url, headers=headers, data=data)

        if response.status_code != 200:
            parse_error(response)
