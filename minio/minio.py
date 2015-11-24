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

import sys
import io
import platform

import urllib3
import certifi
from datetime import datetime

__author__ = "Minio, Inc."

from io import RawIOBase

from .__version__ import get_version
from .acl import is_valid_acl
from .compat import urlsplit, strtype
from .generators import (ListObjectsIterator, ListIncompleteUploadsIterator,
                         ListUploadPartsIterator, DataStreamer)
from .helpers import (get_target_url, is_non_empty_string, is_valid_url,
                      get_sha256, encode_to_base64, get_md5,
                      calculate_part_size, encode_to_hex,
                      is_valid_bucket_name, get_region)
from .parsers import (parse_list_buckets, parse_acl, parse_error,
                      parse_new_multipart_upload)
from .error import ResponseError
from .definitions import Object
from .signer import sign_v4, presign_v4, generate_credential_string, post_presign_signature
from .xml_requests import bucket_constraint, get_complete_multipart_upload
from .post_policy import PostPolicy

class Minio(object):
    def __init__(self, url, access_key=None, secret_key=None, certs=None):
        """
        Creates a new cloud storage client.

        Examples:

          client = Minio('https://play.minio.io:9000')
          client = Minio('https://s3.amazonaws.com', 'ACCESS_KEY', 'SECRET_KEY')

        :param url: A string of the URL of the cloud storage server.
        :param access_key: Access key to sign self._http.request with.
        :param secret_key: Secret key to sign self._http.request with.
        :param certs: Path to SSL certificates
        :return: Minio object
        """
        is_valid_url(url)

        url_components = urlsplit(url)
        self._location = url_components.netloc
        self._endpoint_url = url_components.geturl()
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = 'minio-py/' + get_version() + \
                           ' (' + platform.system() + '; ' + \
                           platform.machine() + ')'
        if certs is None:
            certs = certifi.where()

        self._http = urllib3.PoolManager(
            cert_reqs='CERT_REQUIRED',
            ca_certs=certs
        )

    # Client level
    def set_user_agent(self, name=None, version=None, comments=None):
        """
        Adds an entry to the list of user agents.

        Example:
            minio.add_user_agent('my_app', '1.0.0', ['ex', 'parrot'])
            # Results in my_app/1.0.0 (ex; parrot) appended to user agent

        :param name: user agent name
        :param version: user agent version
        :param comments: list of comments to include in comments section
        :return: None
        """
        if name is None or version is None:
            raise TypeError()
        if not isinstance(name, strtype) or \
           not isinstance(version, strtype):
            raise TypeError()
        if not name.strip() or not version.strip():
            raise ValueError()

        if comments is not None:
            joined_comments = '; '.join(comments)
            components = [' ', name, '/', version, ' (', joined_comments, ')']
            self._user_agent += ''.join(components)
        else:
            components = [' ', name, '/', version, ' ']
            self._user_agent += ''.join(components)

    # Bucket level
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
        is_valid_bucket_name(bucket)
        if acl is not None:
            is_valid_acl(acl)

        method = 'PUT'
        url = get_target_url(self._endpoint_url, bucket=bucket)
        headers = {}

        if acl is not None:
            headers['x-amz-acl'] = acl

        region = get_region(self._location)

        content = ''
        if not (region == 'us-east-1'):
            content = bucket_constraint(region)
            headers['Content-Length'] = str(len(content))

        content_sha256 = get_sha256(content)
        if content.strip():
            content_md5 = encode_to_base64(get_md5(content))
            headers['Content-MD5'] = content_md5


        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key,
                          content_hash=content_sha256)

        response = self._http.urlopen(method, url, body=content,
                                      headers=headers)

        if response.status != 200:
            parse_error(response, bucket)

    def list_buckets(self):
        """
        List all buckets owned by the user.


        Example:
            bucket_list = minio.list_buckets()
            for bucket in bucket_list:
                print bucket.name,bucket.created_date

        :return: A list of buckets owned by the current user.
        """
        url = get_target_url(self._endpoint_url)
        method = 'GET'
        headers = {}


        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers,
                                      redirect=False)

        if response.status != 200:
            try:
                parse_error(response)
            except ResponseError as err:
                if err.code == 'Redirect':
                    err.code = 'AccessDeniedException'
                raise err
        return parse_list_buckets(response.data)

    def bucket_exists(self, bucket):
        """
        Check if the bucket exists and if the user has access to it.

        :param bucket: To test the existence and user access.
        :return: True on success. Otherwise, returns False
        """
        is_valid_bucket_name(bucket)

        method = 'HEAD'
        url = get_target_url(self._endpoint_url, bucket=bucket)
        headers = {}


        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            if response.status == "404":
                return False
            parse_error(response, bucket)

        return True

    def remove_bucket(self, bucket):
        """
        Remove a bucket.

        :param bucket: Bucket to remove
        :return: None
        """
        is_valid_bucket_name(bucket)

        method = 'DELETE'
        url = get_target_url(self._endpoint_url, bucket=bucket)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 204:
            parse_error(response, bucket)

    def get_bucket_acl(self, bucket):
        """
        Get a bucket's canned ACL, if any.

        Example:
            canned_acl = minio.get_bucket_acl('foo')
            if canned_acl == Acl.private():
                # do something

        :param bucket: Bucket to check canned ACL of.
        :return: A string representing canned ACL on the bucket.
        """
        is_valid_bucket_name(bucket)

        method = 'GET'
        url = get_target_url(self._endpoint_url, bucket=bucket,
                             query={"acl": None})
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucket)

        return parse_acl(response.data)

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
        is_valid_bucket_name(bucket)
        is_valid_acl(acl)

        method = 'PUT'
        url = get_target_url(self._endpoint_url, bucket=bucket,
                             query={"acl": None})

        headers = {
            'x-amz-acl': acl,
        }

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucket)

    def presigned_get_object(self, bucket, key, expires=None):
        """
        Presigns a get object request and provides a url
        """
        return self.__presigned_get_partial_object(bucket, key, expires)

    def __presigned_get_partial_object(self, bucket, key, expires=None, offset=0, length=0):
        """
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        request_range = ''
        if offset is not 0 and length is not 0:
            request_range = str(offset) + "-" + str(offset + length - 1)
        if offset is not 0 and length is 0:
            request_range = str(offset) + "-"
        if offset is 0 and length is not 0:
            request_range = "0-" + str(length - 1)

        url = get_target_url(self._endpoint_url, bucket=bucket, key=key)
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        method = 'GET'
        presign_url = presign_v4(method=method, url=url, headers=headers,
                                 access_key=self._access_key,
                                 secret_key=self._secret_key,
                                 expires=expires,
        )
        return presign_url

    def presigned_put_object(self, bucket, key, expires=None):
        """
        Presigns a put object request and provides a url
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        url = get_target_url(self._endpoint_url, bucket=bucket, key=key)
        headers = {}

        method = 'PUT'
        presign_url = presign_v4(method=method, url=url, headers=headers,
                                 access_key=self._access_key,
                                 secret_key=self._secret_key,
                                 expires=expires,
        )
        return presign_url

    def presigned_post_policy(self, form):
        """
        Provides a POST form data that can be used for object upload
        """
        if not isinstance(form, PostPolicy):
            raise InvalidArgumentError('invalid post policy object')

        if not form.is_expiration_set():
            raise InvalidArgumentError('Expiration time must be specified')

        if not form.is_key_set():
            raise InvalidArgumentError('object key must be specified')

        if not form.is_bucket_set():
            raise InvalidArgumentError('bucket name must be specified')

        date = datetime.utcnow()
        iso8601Date = date.strftime("%Y%m%dT%H%M%SZ")
        url = get_target_url(self._endpoint_url, bucket=form.bucket, key=form.key)
        parsed_url = urlsplit(url)
        region = get_region(parsed_url.hostname)

        form.policies.append(('eq', '$x-amz-date', iso8601Date))
        form.policies.append(('eq', '$x-amz-algorithm', 'AWS4-HMAC-SHA256'))
        form.policies.append(('eq', '$x-amz-credential', generate_credential_string(self._access_key, date, region)))

        policy_base64 = form.base64()
        form.form_data['policy'] = policy_base64
        form.form_data['x-amz-algorithm'] = 'AWS4-HMAC-SHA256'
        form.form_data['x-amz-credential'] = generate_credential_string(self._access_key, date, region)
        form.form_data['x-amz-date'] = iso8601Date
        form.form_data['x-amz-signature'] = post_presign_signature(date, region, self._secret_key, policy_base64)
        return form.form_data

    def get_object(self, bucket, key):
        """
        Retrieves an object from a bucket.

        Examples:
            my_partial_object = minio.get_partial_object('foo', 'bar')

        :param bucket: Bucket to retrieve object from
        :param key: Key to retrieve
        :return: An iterable containing a byte stream of the data.
        """
        return self.get_partial_object(bucket, key)

    # Object Level
    def get_partial_object(self, bucket, key, offset=0, length=0):
        """
        Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        Examples:
            my_partial_object = minio.get_partial_object('foo', 'bar', 2, 4)

        :param bucket: Bucket to retrieve object from
        :param key: Key to retrieve
        :param offset: Optional offset to retrieve bytes from. Must be >= 0
        :param length: Optional number of bytes to retrieve. Must be > 0
        :return: An iterable containing a byte stream of the data.
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        request_range = ''
        if offset is not 0 and length is not 0:
            request_range = str(offset) + '-' + str(offset + length - 1)
        if offset is not 0 and length is 0:
            request_range = str(offset) + '-'
        if offset is 0 and length is not 0:
            request_range = '0-' + str(length - 1)

        method = 'GET'
        url = get_target_url(self._endpoint_url, bucket=bucket, key=key)
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers,
                                      preload_content=False)

        if response.status != 206 and response.status != 200:
            parse_error(response, bucket+'/'+key)

        return DataStreamer(response)

    def put_object(self, bucket, key, length, data,
                   content_type='application/octet-stream'):
        """
        Add a new object to the cloud storage server.

        Data can either be a string, byte array, or reader (e.g. open('foo'))

        Examples:
            minio.put('foo', 'bar', 11, 'hello world')

            minio.put('foo', 'bar', 11, b'hello world', 'text/plain')

            with open('hello.txt', 'rb') as data:
                minio.put('foo', 'bar', 11, b'hello world', 'text/plain')

        :param bucket: Bucket of new object.
        :param key: Key of new object.
        :param length: Total length of object.
        :param data: Contents to upload.
        :param content_type: mime type of object as a string.
        :return: None
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        if length is 0:
            raise ValueError('length')

        if length <= 5 * 1024 * 1024:
            # reference 'file' for python 2.7 compatibility, RawIOBase for 3.X
            if type(data).__name__ == 'file' or \
               isinstance(data, io.BufferedReader):
                data = data.read(length)
            if isinstance(data, io.TextIOWrapper):
                data = data.read(length).encode('utf-8')
            if sys.version_info >= (3, 0) and isinstance(data, strtype):
                data = data.encode('utf-8')
            return self._do_put_object(bucket, key, length, data, content_type)
        self._stream_put_object(bucket, key, length, data, content_type)

    def list_objects(self, bucket, prefix=None, recursive=False):
        """
        List objects in the given bucket.

        Examples:
            objects = minio.list_objects('foo')
            for current_object in objects:
                print current_object
            # hello
            # hello/
            # hello/
            # world/

            objects = minio.list_objects('foo', prefix='hello/')
            for current_object in objects:
                print current_object
            # hello/world/

            objects = minio.list_objects('foo', recursive=True)
            for current_object in objects:
                print current_object
            # hello/world/1
            # world/world/2
            # ...

            objects = minio.list_objects('foo', prefix='hello/',
                                         recursive=True)
            for current_object in objects:
                print current_object
            # hello/world/1
            # hello/world/2

        :param bucket: Bucket to list objects from
        :param prefix: String specifying objects returned must begin with
        :param recursive: If yes, returns all objects for a specified prefix
        :return: An iterator of objects in alphabetical order.
        """
        is_valid_bucket_name(bucket)
        return ListObjectsIterator(self._http, self._endpoint_url, bucket,
                                   prefix, recursive, self._access_key,
                                   self._secret_key)

    def stat_object(self, bucket, key):
        """
        Check if an object exists.

        :param bucket: Bucket of object.
        :param key: Key of object
        :return: Object metadata if object exists
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        method = 'HEAD'
        url = get_target_url(self._endpoint_url, bucket=bucket, key=key)
        headers = {}


        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucket+'/'+key)

        content_type = response.headers['content-type']
        etag = response.headers['etag'].replace('"', '')
        size = response.headers['content-length']
        last_modified = response.headers['last-modified']

        return Object(bucket, key, content_type=content_type,
                      last_modified=last_modified, etag=etag, size=size)

    def remove_object(self, bucket, key):
        """
        Remove an object from the bucket.

        :param bucket: Bucket of object to remove
        :param key: Key of object to remove
        :return: None
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        method = 'DELETE'
        url = get_target_url(self._endpoint_url, bucket=bucket, key=key)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers)

        if response.status != 204:
            parse_error(response, bucket+'/'+key)

    def list_incomplete_uploads(self, bucket, prefix=None, recursive=False):
        """
        List all in-complete uploads for a given bucket.

        Examples:
            incomplete_uploads = minio.list_incomplete_uploads('foo')
            for current_upload in incomplete_uploads:
                print current_upload
            # hello
            # hello/
            # hello/
            # world/

            incomplete_uploads = minio.list_incomplete_uploads('foo', prefix='hello/')
            for current_upload in incomplete_uploads:
                print current_upload
            # hello/world/

            incomplete_uploads = minio.list_incomplete_uploads('foo', recursive=True)
            for current_upload in incomplete_uploads:
                print current_upload
            # hello/world/1
            # world/world/2
            # ...

            incomplete_uploads = minio.list_incomplete_uploads('foo', prefix='hello/', recursive=True)
            for current_upload in incomplete_uploads:
                print current_upload
            # hello/world/1
            # hello/world/2

        :param bucket: Bucket to list incomplete uploads
        :param prefix: String specifying objects returned must begin with
        :param recursive: If yes, returns all incomplete uploads for a specified prefix
        :return: None
        """
        is_valid_bucket_name(bucket)
        delimiter = None
        if recursive == False:
            delimiter = '/'
        return ListIncompleteUploadsIterator(self._http, self._endpoint_url,
                                             bucket, prefix,
                                             delimiter,
                                             access_key=self._access_key,
                                             secret_key=self._secret_key)

    def remove_incomplete_upload(self, bucket, key):
        """
        Remove all in-complete uploads for a given bucket and key.

        :param bucket: Bucket to drop incomplete uploads
        :param key: Key of object to drop incomplete uploads of
        :return: None
        """
        is_valid_bucket_name(bucket)
        is_non_empty_string(key)

        # check key
        uploads = ListIncompleteUploadsIterator(self._http, self._endpoint_url,
                                                bucket, key,
                                                access_key=self._access_key,
                                                secret_key=self._secret_key)
        for upload in uploads:
            if key == upload.key:
                self._remove_incomplete_upload(bucket, upload.key, upload.upload_id)
                return

    # helper functions

    def _do_put_object(self, bucket, key, length, data,
                       content_type='application/octet-stream',
                       upload_id='', part_number=0):
        method = 'PUT'

        if len(data) != length:
            raise UnexpectedShortReadError()

        if upload_id.strip() and part_number is not 0:
            url = get_target_url(self._endpoint_url, bucket=bucket, key=key,
                                 query={'uploadId': upload_id,
                                        'partNumber': part_number})
        else:
            url = get_target_url(self._endpoint_url, bucket=bucket, key=key)

        content_sha256 = get_sha256(data)
        content_md5 = encode_to_base64(get_md5(data))

        headers = {
            'Content-Length': length,
            'Content-Type': content_type,
            'Content-MD5': content_md5
        }

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key,
                          content_hash=content_sha256)

        data = io.BytesIO(data)
        response = self._http.urlopen(method, url, headers=headers, body=data)

        if response.status != 200:
            parse_error(response, bucket+'/'+key)

        return response.headers['etag'].replace('"', '')

    def _stream_put_object(self, bucket, key, length, data, content_type):
        ## TODO handle non blocking streams
        if type(data).__name__ != 'file':
            if not isinstance(data, io.BufferedReader):
                if not isinstance(data, RawIOBase):
                    if sys.version_info >= (3, 0):
                        if isinstance(data, strtype):
                            data = data.encode('utf-8')
                    data = io.BytesIO(data)
                data = io.BufferedReader(data)

        part_size = calculate_part_size(length)
        current_uploads = ListIncompleteUploads(self._http,
                                                self._endpoint_url,
                                                bucket,
                                                key,
                                                access_key=self._access_key,
                                                secret_key=self._secret_key)

        upload_id = None
        for upload in current_uploads:
            if key == upload.key:
                upload_id = upload.upload_id

        uploaded_parts = {}
        if upload_id is None:
            upload_id = self._new_multipart_upload(bucket, key, content_type)
        else:
            part_iter = ListUploadPartsIterator(self._http, self._endpoint_url,
                                                bucket, key, upload_id,
                                                access_key=self._access_key,
                                                secret_key=self._secret_key)
            for part in part_iter:
                uploaded_parts[part.part_number] = part

        total_uploaded = 0
        current_part_number = 1
        etags = []
        while total_uploaded < length:
            current_data = data.read(part_size)
            if len(current_data) == 0:
                break
            ## Throw unexpected short read error
            if len(current_data) < part_size:
                if (length - total_uploaded) != len(current_data):
                    raise UnexpectedShortReadError()

            current_data_md5 = encode_to_hex(get_md5(current_data))
            previously_uploaded_part = None
            if current_part_number in uploaded_parts:
                previously_uploaded_part = uploaded_parts[current_part_number]
            if previously_uploaded_part is None or \
               previously_uploaded_part.etag != current_data_md5:
                etag = self._do_put_object(bucket=bucket, key=key,
                                           length=len(current_data),
                                           data=current_data,
                                           content_type=content_type,
                                           upload_id=upload_id,
                                           part_number=current_part_number)
            else:
                etag = previously_uploaded_part.etag
            etags.append(etag)
            total_uploaded += len(current_data)
            current_part_number += 1

        self._complete_multipart_upload(bucket, key, upload_id, etags)

    def _remove_incomplete_upload(self, bucket, key, upload_id):
        method = 'DELETE'
        query = {
            'uploadId': upload_id
        }
        url = get_target_url(self._endpoint_url,
                             bucket=bucket,
                             key=key,
                             query=query)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 204:
            parse_error(response, bucket+'/'+key)

    def _new_multipart_upload(self, bucket, key, content_type):
        method = 'POST'
        query = {
            'uploads': None
        }

        url = get_target_url(self._endpoint_url, bucket=bucket,
                             key=key, query=query)

        headers = {
            'Content-Type': content_type
        }


        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers, body=None)

        if response.status != 200:
            parse_error(response, bucket+'/'+key)

        return parse_new_multipart_upload(response.data)

    def _complete_multipart_upload(self, bucket, key, upload_id, etags):
        method = 'POST'
        query = {
            'uploadId': upload_id
        }
        url = get_target_url(self._endpoint_url, bucket=bucket,
                             key=key, query=query)
        headers = {}

        data = get_complete_multipart_upload(etags)
        data_sha256 = get_sha256(data)
        data_md5 = encode_to_base64(get_md5(data))

        headers['Content-Length'] = len(data)
        headers['Content-Type'] = 'application/xml'
        headers['Content-MD5'] = data_md5


        headers = sign_v4(method=method, url=url, headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=data_sha256)

        response = self._http.urlopen(method, url, headers=headers, body=data)

        if response.status != 200:
            parse_error(response, bucket+'/'+key)
