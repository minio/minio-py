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
minio.api
~~~~~~~~~~~~

This module implements the API.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

# Standard python packages
from __future__ import absolute_import
import platform

from time import mktime, strptime
from datetime import datetime, timedelta

import io
# Dependencies
import urllib3
import certifi

# Internal imports
from . import __title__, __version__
from .compat import urlsplit
from .error import ResponseError, InvalidArgumentError
from .bucket_acl import is_valid_acl
from .definitions import Object
from .generators import (ListObjectsIterator, ListIncompleteUploadsIterator,
                         ListUploadPartsIterator)
from .parsers import (parse_list_buckets, parse_acl,
                      parse_new_multipart_upload,
                      parse_location_constraint)
from .helpers import (get_target_url, is_non_empty_string,
                      is_valid_endpoint, get_sha256,
                      encode_to_base64, get_md5,
                      calculate_part_size, encode_to_hex,
                      is_valid_bucket_name, parts_manager)
from .signer import (sign_v4, presign_v4,
                     generate_credential_string,
                     post_presign_signature)
from .xml_marshal import (xml_marshal_bucket_constraint,
                          xml_marshal_complete_multipart_upload)



# Comment format.
_COMMENTS = '({0}; {1})'
# App info format.
_APP_INFO = '{0}/{1}'

# Minio (OS; ARCH) LIB/VER APP/VER .
_DEFAULT_USER_AGENT = 'Minio {0} {1}'.format(
    _COMMENTS.format(platform.system(),
                     platform.machine()),
    _APP_INFO.format(__title__,
                     __version__))

class Minio(object):
    """
    Constructs a :class:`Minio <Minio>`.

    Examples:
        client = Minio('https://play.minio.io:9000')
        client = Minio('https://s3.amazonaws.com',
                       'ACCESS_KEY', 'SECRET_KEY')

    :param endpoint: A string of the URL of the cloud storage server.
    :param access_key: Access key to sign self._http.request with.
    :param secret_key: Secret key to sign self._http.request with.
    :return: :class:`Minio <Minio>` object
    """
    def __init__(self, endpoint, access_key=None, secret_key=None):
        is_valid_endpoint(endpoint)
        url_components = urlsplit(endpoint)
        self._region_map = dict()
        self._endpoint_url = url_components.geturl()
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = _DEFAULT_USER_AGENT
        self._http = urllib3.PoolManager(
            cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where()
        )

    # Set application information.
    def set_app_info(self, app_name, app_version):
        """
        Sets your application name and version to
        default user agent in the following format.

              Minio (OS; ARCH) LIB/VER APP/VER

        Example:
            client.set_app_info('my_app', '1.0.0')

        :param app_name: application name.
        :param app_version: application version.
        """
        if not (app_name and app_version):
            raise ValueError('app_name and app_version cannot be empty.')

        app_info = _APP_INFO.format(app_name,
                                    app_version)
        self._user_agent = ' '.join([_DEFAULT_USER_AGENT, app_info])

    # Bucket level
    def make_bucket(self, bucket_name, location='us-east-1', acl=None):
        """
        Make a new bucket on the server.

        Optionally include Location.
           ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'sa-east-1',
            'cn-north-1']

        Optionally include an ACL. Valid ACLs are as follows:
            Acl.public_read_write()
            Acl.public_read()
            Acl.authenticated_read()
            Acl.private()

        Examples:
            minio.make_bucket('foo')
            minio.make_bucket('foo', 'us-west-1')

        :param bucket_name: Bucket to create on server
        :param location: Location to create bucket on
        """
        if acl is not None:
            is_valid_acl(acl)

        is_valid_bucket_name(bucket_name)

        method = 'PUT'
        url = get_target_url(self._endpoint_url, bucket_name=bucket_name)
        headers = {}

        if acl is not None:
            headers['x-amz-acl'] = acl

        content = ''
        if location != 'us-east-1':
            content = xml_marshal_bucket_constraint(location)
            headers['Content-Length'] = str(len(content))

        content_sha256_hex = encode_to_hex(get_sha256(content))
        if content.strip():
            content_md5_base64 = encode_to_base64(get_md5(content))
            headers['Content-MD5'] = content_md5_base64

        response = self._url_open(method, url, location,
                                  body=content, headers=headers,
                                  content_sha256=content_sha256_hex)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.put(bucket_name)

        self._set_region(bucket_name, region=location)

    def list_buckets(self):
        """
        List all buckets owned by the user.

        Example:
            bucket_list = minio.list_buckets()
            for bucket in bucket_list:
                print(bucket.name, bucket.created_date)

        :return: An iterator of buckets owned by the current user.
        """

        method = 'GET'
        headers = {}
        url = get_target_url(self._endpoint_url)

        # default for all requests.
        region = 'us-east-1'

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get()

        return parse_list_buckets(response.data)

    def bucket_exists(self, bucket_name):
        """
        Check if the bucket exists and if the user has access to it.

        :param bucket_name: To test the existence and user access.
        :return: True on success.
        """
        is_valid_bucket_name(bucket_name)

        method = 'HEAD'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url, bucket_name=bucket_name)
        headers = {}

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.head(bucket_name)

        return True

    def remove_bucket(self, bucket_name):
        """
        Remove a bucket.

        :param bucket_name: Bucket to remove
        """
        is_valid_bucket_name(bucket_name)

        method = 'DELETE'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url, bucket_name=bucket_name)
        headers = {}

        response = self._url_open(method, url, region,
                                  headers=headers)
        if response.status != 204:
            response_error = ResponseError(response)
            raise response_error.delete(bucket_name)

    def get_bucket_acl(self, bucket_name):
        """
        Get a bucket's canned ACL, if any.

        Example:
            canned_acl = minio.get_bucket_acl('foo')
            if canned_acl == Acl.private():
                # do something

        :param bucket_name: Bucket to check canned ACL of.
        :return: A string representing canned ACL on the bucket.
        """
        is_valid_bucket_name(bucket_name)

        method = 'GET'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             query={"acl": None})
        headers = {}

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get(bucket_name)

        return parse_acl(response.data)

    def set_bucket_acl(self, bucket_name, acl):
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

        :param bucket_name: Bucket to set ACL for.
        :param acl: ACL to set.
        """
        is_valid_bucket_name(bucket_name)
        is_valid_acl(acl)

        method = 'PUT'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             query={"acl": None})

        headers = {
            'x-amz-acl': acl,
        }

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.put(bucket_name)

    def presigned_get_object(self, bucket_name, object_name,
                             expires=timedelta(days=7)):
        """
        Presigns a get object request and provides a url

        Example:

            from datetime import timedelta

            presignedURL = presigned_get_object('bucket_name',
                                                'object_name',
                                                timedelta(days=7))
            print(presignedURL)

        :param bucket_name: Bucket for the presigned url.
        :param object_name: Object for which presigned url is generated.
        :param expires: Optional expires argument to specify timedelta.
           Defaults to 7days.
        :return: Presigned url.
        """
        if expires.total_seconds() < 1 or expires.total_seconds() > 604800:
            raise InvalidArgumentError('Expires param valid values are'
                                       ' between 1 secs to 604800 secs')

        return self.__presigned_get_partial_object(bucket_name,
                                                   object_name,
                                                   expires)

    def __presigned_get_partial_object(self, bucket_name, object_name,
                                       expires=timedelta(days=7),
                                       offset=0, length=0):
        """
        Presigns a get partial object request and provides a url,
        this is a internal function not exposed.

        :param bucket_name: Bucket for the presigned url.
        :param object_name: Object for which presigned url is generated.
        :param expires: optional expires argument to specify timedelta.
           Defaults to 7days.
        :param offset, length: optional defaults to '0, 0'.
        :return: Presigned url.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        request_range = ''
        if offset is not 0 and length is not 0:
            request_range = str(offset) + "-" + str(offset + length - 1)
        if offset is not 0 and length is 0:
            request_range = str(offset) + "-"
        if offset is 0 and length is not 0:
            request_range = "0-" + str(length - 1)

        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name)
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        method = 'GET'
        presign_url = presign_v4(method, url,
                                 self._access_key,
                                 self._secret_key,
                                 region=region,
                                 headers=headers,
                                 expires=int(expires.total_seconds()))
        return presign_url

    def presigned_put_object(self, bucket_name, object_name,
                             expires=timedelta(days=7)):
        """
        Presigns a put object request and provides a url

        Example:
            from datetime import timedelta

            presignedURL = presigned_put_object('bucket_name',
                                                'object_name',
                                                timedelta(days=7))
            print(presignedURL)

        :param bucket_name: Bucket for the presigned url.
        :param object_name: Object for which presigned url is generated.
        :param expires: optional expires argument to specify timedelta.
           Defaults to 7days.
        :return: Presigned put object url.
        """
        if expires.total_seconds() < 1 or expires.total_seconds() > 604800:
            raise InvalidArgumentError('Expires param valid values are'
                                       ' between 1 secs to 604800 secs')

        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name)
        headers = {}

        method = 'PUT'
        presign_url = presign_v4(method, url,
                                 self._access_key,
                                 self._secret_key,
                                 region=region,
                                 headers=headers,
                                 expires=int(expires.total_seconds()))
        return presign_url

    def presigned_post_policy(self, policy):
        """
        Provides a POST form data that can be used for object uploads.

        Example:
            policy = PostPolicy()
            policy.set_bucket_name('bucket_name')
            policy.set_key_startswith('objectPrefix/')

            expires_date = datetime.utcnow()+timedelta(days=10)
            policy.set_expires(expires_date)

            print(presigned_post_policy(policy))

        :param policy: Policy object.
        :return: Policy form dictionary to be used in curl or HTML forms.
        """
        if not policy:
            raise InvalidArgumentError('Policy cannot be NoneType.')

        if not policy.is_expiration_set():
            raise InvalidArgumentError('Expiration time must be specified.')

        if not policy.is_bucket_set():
            raise InvalidArgumentError('bucket name must be specified.')

        if not policy.is_key_set():
            raise InvalidArgumentError('object key must be specified.')

        date = datetime.utcnow()
        iso8601_date = date.strftime("%Y%m%dT%H%M%SZ")
        region = self._get_region(policy.form_data['bucket'])
        credential_string = generate_credential_string(self._access_key,
                                                       date, region)
        policy.policies.append(('eq', '$x-amz-date',
                                iso8601_date))
        policy.policies.append(('eq',
                                '$x-amz-algorithm',
                                'AWS4-HMAC-SHA256'))
        policy.policies.append(('eq',
                                '$x-amz-credential',
                                credential_string))

        policy_base64 = policy.base64()
        policy.form_data['policy'] = policy_base64
        policy.form_data['x-amz-algorithm'] = 'AWS4-HMAC-SHA256'
        policy.form_data['x-amz-credential'] = credential_string
        policy.form_data['x-amz-date'] = iso8601_date
        signature = post_presign_signature(date, region,
                                           self._secret_key,
                                           policy_base64)
        policy.form_data['x-amz-signature'] = signature
        return policy.form_data

    def get_object(self, bucket_name, object_name):
        """
        Retrieves an object from a bucket.

        Examples:
            my_partial_object = minio.get_partial_object('foo', 'bar')

        :param bucket_name: Bucket to read object from
        :param object_name: Name of object to read
        :return: :class:`urllib3.response.HTTPResponse` object.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        response = self._get_partial_object(bucket_name,
                                            object_name)
        return response

    def get_partial_object(self, bucket_name, object_name, offset=0, length=0):
        """
        Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        Examples:
            partial_object = minio.get_partial_object('foo', 'bar', 2, 4)

        :param bucket_name: Bucket to retrieve object from
        :param object_name: Name of object to retrieve
        :param offset: Optional offset to retrieve bytes from.
           Must be >= 0.
        :param length: Optional number of bytes to retrieve.
           Must be an integer.
        :return: :class:`urllib3.response.HTTPResponse` object.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        response = self._get_partial_object(bucket_name,
                                            object_name,
                                            offset, length)
        return response

    # Object Level
    def _get_partial_object(self, bucket_name, object_name,
                            offset=0, length=0):
        """
        Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        Examples:
            partial_object = minio.get_partial_object('foo', 'bar', 2, 4)

        :param bucket_name: Bucket to retrieve object from
        :param object_name: Name of object to retrieve
        :param offset: Optional offset to retrieve bytes from.
           Must be >= 0.
        :param length: Optional number of bytes to retrieve.
           Must be an integer.
        :return: :class:`urllib3.response.HTTPResponse` object.
        """
        request_range = ''
        if offset is not 0 and length is not 0:
            request_range = str(offset) + '-' + str(offset + length - 1)
        if offset is not 0 and length is 0:
            request_range = str(offset) + '-'
        if length < 0 and offset == 0:
            request_range = '%d' % length
        if offset is 0 and length is not 0:
            request_range = '0-' + str(length - 1)

        method = 'GET'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name)
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 206 and response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get(bucket_name, object_name)

        return response

    def put_object(self, bucket_name, object_name, data, length,
                   content_type='application/octet-stream'):
        """
        Add a new object to the cloud storage server.

        Examples:
         with open('hello.txt', 'rb') as data:
             minio.put_object('foo', 'bar', data, -1, 'text/plain')

        - For length lesser than 5MB put_object automatically
          does single Put operation.
        - For length equal to 0Bytes put_object automatically
          does single Put operation.
        - For length larger than 5MB put_object automatically
          does resumable multipart operation.
        - For length input as -1 put_object treats it as a
          stream and does multipart operation until  input stream
          reaches EOF. Maximum object size that can be uploaded
          through this operation will be 5TB.

        :param bucket_name: Bucket of new object.
        :param object_name: Name of new object.
        :param data: Contents to upload.
        :param length: Total length of object.
        :param content_type: mime type of object as a string.
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        if length > 5 * 1024 * 1024:
            return self._stream_put_object(bucket_name, object_name,
                                           data, length, content_type)

        current_data = data.read(length)
        current_data_md5_base64 = encode_to_base64(get_md5(current_data))
        current_data_sha256_hex = encode_to_hex(get_sha256(current_data))
        return self._do_put_object(bucket_name, object_name,
                                   io.BytesIO(current_data),
                                   current_data_md5_base64,
                                   current_data_sha256_hex,
                                   length, content_type)

    def list_objects(self, bucket_name, prefix=None, recursive=False):
        """
        List objects in the given bucket.

        Examples:
            objects = minio.list_objects('foo')
            for current_object in objects:
                print(current_object)
            # hello
            # hello/
            # hello/
            # world/

            objects = minio.list_objects('foo', prefix='hello/')
            for current_object in objects:
                print(current_object)
            # hello/world/

            objects = minio.list_objects('foo', recursive=True)
            for current_object in objects:
                print(current_object)
            # hello/world/1
            # world/world/2
            # ...

            objects = minio.list_objects('foo', prefix='hello/',
                                         recursive=True)
            for current_object in objects:
                print(current_object)
            # hello/world/1
            # hello/world/2

        :param bucket_name: Bucket to list objects from
        :param prefix: String specifying objects returned must begin with
        :param recursive: If yes, returns all objects for a specified prefix
        :return: An iterator of objects in alphabetical order.
        """
        is_valid_bucket_name(bucket_name)
        return ListObjectsIterator(self._http, self._endpoint_url,
                                   bucket_name,
                                   prefix, recursive,
                                   access_key=self._access_key,
                                   secret_key=self._secret_key,
                                   region=self._get_region(bucket_name))

    def stat_object(self, bucket_name, object_name):
        """
        Check if an object exists.

        :param bucket_name: Bucket of object.
        :param object_name: Name of object
        :return: Object metadata if object exists
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        method = 'HEAD'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name)
        headers = {}

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.head(bucket_name, object_name)

        http_time_format = "%a, %d %b %Y %H:%M:%S GMT"
        etag = ''
        size = 0
        content_type = ''
        last_modified = None
        if 'etag' in response.headers:
            etag = response.headers['etag'].replace('"', '')
        if 'content-length' in response.headers:
            size = int(response.headers['content-length'])
        if 'content-type' in response.headers:
            content_type = response.headers['content-type']
        if 'last-modified' in response.headers:
            last_modified = mktime(strptime(response.headers['last-modified'],
                                            http_time_format))
        return Object(bucket_name, object_name, content_type=content_type,
                      last_modified=last_modified, etag=etag, size=size)

    def remove_object(self, bucket_name, object_name):
        """
        Remove an object from the bucket.

        :param bucket_name: Bucket of object to remove
        :param object_name: Name of object to remove
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        method = 'DELETE'
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name)
        headers = {}

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 204:
            response_error = ResponseError(response)
            raise response_error.delete(bucket_name, object_name)

    def list_incomplete_uploads(self, bucket_name, prefix=None,
                                recursive=False):
        """
        List all in-complete uploads for a given bucket.

        Examples:
            incomplete_uploads = minio.list_incomplete_uploads('foo')
            for current_upload in incomplete_uploads:
                print(current_upload)
            # hello
            # hello/
            # hello/
            # world/

            incomplete_uploads = minio.list_incomplete_uploads('foo',
                                                               prefix='hello/')
            for current_upload in incomplete_uploads:
                print(current_upload)
            # hello/world/

            incomplete_uploads = minio.list_incomplete_uploads('foo',
                                                               recursive=True)
            for current_upload in incomplete_uploads:
                print(current_upload)
            # hello/world/1
            # world/world/2
            # ...

            incomplete_uploads = minio.list_incomplete_uploads('foo',
                                                               prefix='hello/',
                                                               recursive=True)
            for current_upload in incomplete_uploads:
                print(current_upload)
            # hello/world/1
            # hello/world/2

        :param bucket_name: Bucket to list incomplete uploads
        :param prefix: String specifying objects returned must begin with
        :param recursive: If yes, returns all incomplete uploads for
           a specified prefix
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        delimiter = '/'
        if recursive is True:
            delimiter = None
        region = self._get_region(bucket_name)
        # get the uploads_iter.
        uploads_iter = ListIncompleteUploadsIterator(self._http,
                                                     self._endpoint_url,
                                                     bucket_name,
                                                     prefix=prefix,
                                                     delimiter=delimiter,
                                                     access_key=self._access_key,
                                                     secret_key=self._secret_key,
                                                     region=region)

        # range over uploads_iter.
        for upload in uploads_iter:
            upload.size = 0
            # Use upload metadata to gather total parts size.
            part_iter = ListUploadPartsIterator(self._http,
                                                self._endpoint_url,
                                                upload.bucket_name,
                                                upload.object_name,
                                                upload.upload_id,
                                                self._access_key,
                                                self._secret_key,
                                                region)
            total_uploaded_size = 0
            for part in part_iter:
                total_uploaded_size += part.size

            # update total part size and yield.
            upload.size = total_uploaded_size
            yield upload

    def remove_incomplete_upload(self, bucket_name, object_name):
        """
        Remove all in-complete uploads for a given bucket_name and object_name.

        :param bucket_name: Bucket to drop incomplete uploads
        :param object_name: Name of object to remove incomplete uploads
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        region = self._get_region(bucket_name)
        # check key
        uploads = ListIncompleteUploadsIterator(self._http, self._endpoint_url,
                                                bucket_name, prefix=object_name,
                                                delimiter='',
                                                access_key=self._access_key,
                                                secret_key=self._secret_key,
                                                region=region)
        for upload in uploads:
            if object_name == upload.object_name:
                self._remove_incomplete_upload(bucket_name, object_name,
                                               upload.upload_id)
                return

    def _do_put_multipart_object(self, bucket_name, object_name, data,
                                 data_md5_base64,
                                 data_sha256_hex,
                                 data_content_size,
                                 data_content_type='application/octet-stream',
                                 upload_id='', part_number=0):
        """
        Initiate a multipart PUT operation for a part number.

        :param bucket_name: Bucket name for the multipart request.
        :param object_name: Object name for the multipart request.
        :param data: Input data for the multipart request.
        :param data_md5_base64: Base64 md5 of data.
        :param data_sha256_hex: Hexadecimal sha256 of data.
        :param data_content_size: Input data size.
        :param data_content_type: Content type of multipart request.
        :param upload_id: Upload id of the multipart request.
        :param part_number: Part number of the data to be uploaded.
        """

        method = 'PUT'
        region = self._get_region(bucket_name)

        url = get_target_url(self._endpoint_url, bucket_name=bucket_name,
                             object_name=object_name,
                             query={'uploadId': upload_id,
                                    'partNumber': part_number})

        headers = {
            'Content-Length': data_content_size,
            'Content-Type': data_content_type,
            'Content-MD5': data_md5_base64
        }

        response = self._url_open(method, url, region,
                                  headers=headers,
                                  body=data,
                                  content_sha256=data_sha256_hex)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.put(bucket_name, object_name)

        return response.headers['etag'].replace('"', '')

    def _do_put_object(self, bucket_name, object_name, data,
                       data_md5_base64,
                       data_sha256_hex,
                       data_content_size,
                       data_content_type='application/octet-stream'):
        """
        Initiate a single PUT operation.

        :param bucket_name: Bucket name for the put request.
        :param object_name: Object name for the put request.
        :param data: Input data for the put request.
        :param data_md5_base64: Base64 md5 of data.
        :param data_sha256_hex: Hexadecimal sha256 of data.
        :param data_content_size: Input data size.
        :param data_content_type: Content type of put request.
        """

        method = 'PUT'
        region = self._get_region(bucket_name)

        url = get_target_url(self._endpoint_url, bucket_name=bucket_name,
                             object_name=object_name)

        headers = {
            'Content-Length': data_content_size,
            'Content-Type': data_content_type,
            'Content-MD5': data_md5_base64
        }

        response = self._url_open(method, url, region,
                                  headers=headers,
                                  body=data,
                                  content_sha256=data_sha256_hex)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.put(bucket_name, object_name)

        return response.headers['etag'].replace('"', '')

    def _stream_put_object(self, bucket_name,
                           object_name, data,
                           data_content_size,
                           data_content_type='application/octet-stream'):
        """
        Streaming multipart upload operation.

        :param bucket_name: Bucket name of the multipart upload.
        :param object_name: Object name of the multipart upload.
        :param data_content_size: Total size of the content to be uploaded.
        :param data_content_type: Content type of of the multipart upload.
           Defaults to 'application/octet-stream'.
        """
        part_size = calculate_part_size(data_content_size)
        region = self._get_region(bucket_name)
        current_uploads = ListIncompleteUploadsIterator(self._http,
                                                        self._endpoint_url,
                                                        bucket_name,
                                                        prefix=object_name,
                                                        delimiter='',
                                                        access_key=self._access_key,
                                                        secret_key=self._secret_key,
                                                        region=region)
        upload_id = None
        for upload in current_uploads:
            if object_name == upload.object_name:
                upload_id = upload.upload_id

        # Initialize variables
        uploaded_parts = {}
        uploaded_etags = []
        total_uploaded = 0
        current_part_number = 1

        # Some streams wouldn't implement seek() method.
        # Handle it and set it to False.
        is_seekable_stream = False
        if hasattr(data, 'seek'):
            is_seekable_stream = True

        # If upload_id is None its a new multipart upload.
        if upload_id is None:
            upload_id = self._new_multipart_upload(bucket_name,
                                                   object_name,
                                                   data_content_type)
        else:
            # Iter over the uploaded parts.
            part_iter = ListUploadPartsIterator(self._http,
                                                self._endpoint_url,
                                                bucket_name,
                                                object_name,
                                                upload_id,
                                                self._access_key,
                                                self._secret_key,
                                                region)
            uploaded_parts_size = 0
            latest_part_number = 0
            for part in part_iter:
                # Save total uploaded parts size for potential seek offset.
                uploaded_parts_size += part.size
                # Save uploaded parts for future verification.
                uploaded_parts[part.part_number] = part
                # Save the latest_part_numer to indicate
                # previously uploaded part.
                latest_part_number = part.part_number
                # Save uploaded tags for future use.
                uploaded_etags.append(part.etag)

            # If uploaded parts size is greater than zero and seekable.
            # seek to the uploaded parts size.
            if uploaded_parts_size > 0 and is_seekable_stream:
                # Seek to uploaded parts size offset.
                data.seek(uploaded_parts_size)
                # Starts uploading from next part.
                current_part_number = latest_part_number + 1
                # Save total_uploaded for future use.
                total_uploaded = uploaded_parts_size

        # Generate new parts and upload <= part_size until total_uploaded
        # reaches actual data_content_size. Additionally part_manager()
        # also provides md5digest and sha256digest for the partitioned data.
        while True:
            part_metadata = parts_manager(data, part_size)
            current_data_md5_hex = encode_to_hex(part_metadata.md5digest)
            # This code block is only needed when the stream is non
            # seekable, but we still verify md5sum to not upload the
            # same part. Make sure that code is traversed only when
            # input stream is not seekable.
            if is_seekable_stream is False:
                # Verify if current part number has been already uploaded.
                # Further verify if we have matching md5sum as well.
                if current_part_number in uploaded_parts:
                    previous_part = uploaded_parts[current_part_number]
                    if previous_part.etag == current_data_md5_hex:
                        uploaded_etags.append(previous_part.etag)
                        total_uploaded += previous_part.size
                        continue
            current_data_md5_base64 = encode_to_base64(part_metadata.md5digest)
            current_data_sha256_hex = encode_to_hex(part_metadata.sha256digest)
            # Seek back to starting position.
            part_metadata.data.seek(0)
            etag = self._do_put_multipart_object(bucket_name,
                                                 object_name,
                                                 part_metadata.data,
                                                 current_data_md5_base64,
                                                 current_data_sha256_hex,
                                                 part_metadata.size,
                                                 data_content_type,
                                                 upload_id,
                                                 current_part_number)
            # Save etags.
            uploaded_etags.append(etag)
            # If total_uploaded equal to data_content_size break the loop.
            if total_uploaded == data_content_size:
                break
            current_part_number += 1
            total_uploaded += part_metadata.size

        # Complete all multipart transactions if possible.
        self._complete_multipart_upload(bucket_name, object_name,
                                        upload_id, uploaded_etags)

    def _remove_incomplete_upload(self, bucket_name, object_name, upload_id):
        """
        Remove incomplete multipart request.

        :param bucket_name: Bucket name of the incomplete upload.
        :param object_name: Object name of incomplete upload.
        :param upload_id: Upload id of the incomplete upload.
        """
        method = 'DELETE'
        query = {
            'uploadId': upload_id
        }

        region = self._get_region(bucket_name)

        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name,
                             query=query)
        headers = {}

        response = self._url_open(method, url,
                                  region, headers=headers)

        if response.status != 204:
            response_error = ResponseError(response)
            raise response_error.delete(bucket_name, object_name)

    def _new_multipart_upload(self, bucket_name, object_name, content_type):
        """
        Initialize new multipart upload request.

        :param bucket_name: Bucket name of the new multipart request.
        :param object_name: Object name of the new multipart request.
        :param content_type: Content type of the new object.
        :return: Returns an upload id.
        """
        method = 'POST'
        query = {
            'uploads': None
        }

        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name, query=query)

        headers = {'Content-Type': content_type}

        response = self._url_open(method, url, region,
                                  headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.post(bucket_name, object_name)

        return parse_new_multipart_upload(response.data)

    def _complete_multipart_upload(self, bucket_name, object_name,
                                   upload_id, etags):
        """
        Complete an active multipart upload request.

        :param bucket_name: Bucket name of the multipart request.
        :param object_name: Object name of the multipart request.
        :param upload_id: Upload id of the active multipart request.
        """

        method = 'POST'
        query = {
            'uploadId': upload_id
        }
        region = self._get_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name, query=query)
        headers = {}

        data = xml_marshal_complete_multipart_upload(etags)
        data_md5_base64 = encode_to_base64(get_md5(data))
        data_sha256_hex = encode_to_hex(get_sha256(data))

        headers['Content-Length'] = len(data)
        headers['Content-Type'] = 'application/xml'
        headers['Content-MD5'] = data_md5_base64

        response = self._url_open(method, url, region,
                                  headers=headers,
                                  body=data,
                                  content_sha256=data_sha256_hex)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.post(bucket_name, object_name)

    def _set_region(self, bucket_name, region=None):
        """
        Set region based on the bucket name.

        :param bucket_name: Bucket name for which region will be set in
           region map.
        :param region: Optional region, if set location is not fetched.
        """
        # fetch bucket location only for Amazon S3.
        if 'amazonaws.com' in self._endpoint_url:
            if not region:
                region = self._get_bucket_location(bucket_name)
            self._region_map[bucket_name] = region
            return region
        return region

    def _get_region(self, bucket_name):
        """
        Get region based on the bucket name.

        :param bucket_name: Bucket name for which region will be fetched.
        :return: region of bucket name is returned.
        """
        # get proper location only for Amazon S3.
        if 'amazonaws.com' in self._endpoint_url:
            if bucket_name in self._region_map:
                return self._region_map[bucket_name]
            return self._set_region(bucket_name)
        return 'us-east-1'

    def _get_bucket_location(self, bucket_name):
        """
        Get bucket location.

        :param bucket_name: Fetches location of the Bucket name.
        :return: location of bucket name is returned.
        """
        method = 'GET'
        url = self._endpoint_url + '/' + bucket_name + '?location'
        headers = {}
        # default for all requests.
        region = 'us-east-1'

        # For anonymous requests no need to get bucket location.
        if self._access_key is None or self._secret_key is None:
            return 'us-east-1'

        response = self._url_open(method, url, region, headers=headers)
        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get(bucket_name)

        location = parse_location_constraint(response.data)
        # location is empty for 'US standard region'
        if not location:
            return 'us-east-1'
        # location can be 'EU' convert it to meaningful 'eu-west-1'
        if location is 'EU':
            return 'eu-west-1'
        return location

    def _url_open(self, method, url, region, body=None,
                  headers=None, content_sha256=None):
        """
        Open a url wrapper around signature version '4'
           and :meth:`urllib3.PoolManager.urlopen`
        """
        # Set user agent once before the request.
        headers['User-Agent'] = self._user_agent
        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers, self._access_key,
                          self._secret_key, content_sha256)
        return self._http.urlopen(method, url,
                                  body=body,
                                  headers=headers,
                                  preload_content=False)
