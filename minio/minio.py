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
import threading
import tempfile
import hashlib

import urllib3
import certifi
from datetime import datetime

__author__ = "Minio, Inc."

from io import RawIOBase

from .__version__ import get_version
from .acl import is_valid_acl
from .compat import urlsplit, strtype
from .generators import (ListObjectsIterator, ListIncompleteUploadsIterator, ListUploadPartsIterator)
from .helpers import (get_target_url, is_non_empty_string, is_valid_endpoint, get_sha256,
                      encode_to_base64, get_md5, calculate_part_size, encode_to_hex,
                      is_valid_bucket_name, parts_manager)
from .parsers import (parse_list_buckets, parse_acl, parse_error,
                      parse_new_multipart_upload, parse_location_constraint)
from .error import ResponseError
from .definitions import Object
from .signer import sign_v4, presign_v4, generate_credential_string, post_presign_signature
from .xml_requests import bucket_constraint, get_complete_multipart_upload
from .post_policy import PostPolicy
from .acl import Acl

class Minio(object):
    def __init__(self, endpoint, access_key=None, secret_key=None):
        """
        Creates a new cloud storage client.

        Examples:
          client = Minio('https://play.minio.io:9000')
          client = Minio('https://s3.amazonaws.com', 'ACCESS_KEY', 'SECRET_KEY')

        :param endpoint: A string of the URL of the cloud storage server.
        :param access_key: Access key to sign self._http.request with.
        :param secret_key: Secret key to sign self._http.request with.
        :return: Minio object
        """
        is_valid_endpoint(endpoint)

        url_components = urlsplit(endpoint)
        self._region_map = dict()
        self._endpoint_url = url_components.geturl()
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = 'minio-py/' + get_version() + \
                           ' (' + platform.system() + '; ' + \
                           platform.machine() + ')'

        self._http = urllib3.PoolManager(
            cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where()
        )

    # Client level
    def set_app_info(self, name, version, comments=None):
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
        if name == '' or version == '':
            raise ValueError

        if comments is not None:
            joined_comments = '; '.join(comments)
            components = [' ', name, '/', version, ' (', joined_comments, ')']
            self._user_agent += ''.join(components)
        else:
            components = [' ', name, '/', version, ' ']
            self._user_agent += ''.join(components)

    # Bucket level
    def make_bucket(self, bucketName, location='us-east-1', acl=None):
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

        :param bucket: Bucket to create on server
        :param location: Location to create bucket on
        :return:
        """

        if acl is not None:
            is_valid_acl(acl)

        is_valid_bucket_name(bucketName)

        method = 'PUT'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url, bucketName=bucketName)
        headers = {}

        if acl is not None:
            headers['x-amz-acl'] = acl

        content = ''
        if not (location == 'us-east-1'):
            content = bucket_constraint(location)
            headers['Content-Length'] = str(len(content))

        content_sha256_hex = encode_to_hex(get_sha256(content))
        if content.strip():
            content_md5_base64 = encode_to_base64(get_md5(content))
            headers['Content-MD5'] = content_md5_base64

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key,
                          content_sha256=content_sha256_hex)

        response = self._http.urlopen(method, url, body=content,
                                      headers=headers)

        if response.status != 200:
            parse_error(response, bucketName)

        self._set_region(bucket, region=location)

    def list_buckets(self):
        """
        List all buckets owned by the user.

        Example:
            bucket_list = minio.list_buckets()
            for bucket in bucket_list:
                print bucket.name,bucket.created_date

        :return: A list of buckets owned by the current user.
        """

        method = 'GET'
        headers = {}
        url = get_target_url(self._endpoint_url)

        headers = sign_v4(method=method, url=url,
                          region='us-east-1',
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url,
                                      headers=headers,
                                      redirect=False)

        if response.status != 200:
            try:
                parse_error(response)
            except ResponseError as err:
                if err.code == 'Redirect':
                    err.code = 'AccessDeniedException'
                raise err
        return parse_list_buckets(response.data)

    def bucket_exists(self, bucketName):
        """
        Check if the bucket exists and if the user has access to it.

        :param bucket: To test the existence and user access.
        :return: True on success. Otherwise, returns False
        """
        is_valid_bucket_name(bucketName)

        method = 'HEAD'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url, bucketName=bucketName)
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            if response.status == "404":
                return False
            parse_error(response, bucketName)

        return True

    def remove_bucket(self, bucketName):
        """
        Remove a bucket.

        :param bucket: Bucket to remove
        :return: None
        """
        is_valid_bucket_name(bucketName)

        method = 'DELETE'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url, bucketName=bucketName)
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 204:
            parse_error(response, bucketName)

    def get_bucket_acl(self, bucketName):
        """
        Get a bucket's canned ACL, if any.

        Example:
            canned_acl = minio.get_bucket_acl('foo')
            if canned_acl == Acl.private():
                # do something

        :param bucket: Bucket to check canned ACL of.
        :return: A string representing canned ACL on the bucket.
        """
        is_valid_bucket_name(bucketName)

        method = 'GET'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             query={"acl": None})
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucketName)

        return parse_acl(response.data)

    def set_bucket_acl(self, bucketName, acl):
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
        is_valid_bucket_name(bucketName)
        is_valid_acl(acl)

        method = 'PUT'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             query={"acl": None})

        headers = {
            'x-amz-acl': acl,
        }

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucketName)

    def presigned_get_object(self, bucketName, objectName, expires=604800):
        """
        Presigns a get object request and provides a url
        """
        if expires < 1 or expires > 604800:
            raise InvalidArgumentError('expires param valid values are between 1 secs to 604800 secs')

        return self.__presigned_get_partial_object(bucketName, objectName, expires)

    def __presigned_get_partial_object(self, bucketName, objectName, expires=604800, offset=0, length=0):
        """
        """
        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        request_range = ''
        if offset is not 0 and length is not 0:
            request_range = str(offset) + "-" + str(offset + length - 1)
        if offset is not 0 and length is 0:
            request_range = str(offset) + "-"
        if offset is 0 and length is not 0:
            request_range = "0-" + str(length - 1)

        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName)
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        method = 'GET'
        presign_url = presign_v4(method=method, url=url,
                                 region=region,
                                 headers=headers,
                                 access_key=self._access_key,
                                 secret_key=self._secret_key,
                                 expires=expires,
        )
        return presign_url

    def presigned_put_object(self, bucketName, objectName, expires=604800):
        """
        Presigns a put object request and provides a url
        """
        if expires < 1 or expires > 604800:
            raise InvalidArgumentError('expires param valid values are between 1 secs to 604800 secs')

        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName)
        headers = {}

        method = 'PUT'
        presign_url = presign_v4(method=method, url=url,
                                 region=region,
                                 headers=headers,
                                 access_key=self._access_key,
                                 secret_key=self._secret_key,
                                 expires=expires,
        )
        return presign_url

    def presigned_post_policy(self, policy=None):
        """
        Provides a POST form data that can be used for object upload
        """
        if policy is None:
            raise InvalidArgumentError('Policy cannot be NoneType.')

        if not policy.is_expiration_set():
            raise InvalidArgumentError('Expiration time must be specified.')

        if not policy.is_bucket_set():
            raise InvalidArgumentError('bucket name must be specified.')

        if not policy.is_key_set():
            raise InvalidArgumentError('object key must be specified.')

        date = datetime.utcnow()
        iso8601Date = date.strftime("%Y%m%dT%H%M%SZ")
        region = self._get_region(policy.form_data['bucket'])
        credential_string = generate_credential_string(self._access_key, date, region)
        policy.policies.append(('eq', '$x-amz-date', iso8601Date))
        policy.policies.append(('eq', '$x-amz-algorithm', 'AWS4-HMAC-SHA256'))
        policy.policies.append(('eq', '$x-amz-credential', credential_string))

        policy_base64 = policy.base64()
        policy.form_data['policy'] = policy_base64
        policy.form_data['x-amz-algorithm'] = 'AWS4-HMAC-SHA256'
        policy.form_data['x-amz-credential'] = credential_string
        policy.form_data['x-amz-date'] = iso8601Date
        policy.form_data['x-amz-signature'] = post_presign_signature(date, region, self._secret_key, policy_base64)
        return policy.form_data

    def get_object(self, bucketName, objectName):
        """
        Retrieves an object from a bucket.

        Examples:
            my_partial_object = minio.get_partial_object('foo', 'bar')

        :param bucketName: Bucket to read object from
        :param objectName: Name of object to read
        :return: An iterable containing stream of the data.
        """
        return self.get_partial_object(bucketName, objectName)

    # Object Level
    def get_partial_object(self, bucketName, objectName, offset=0, length=0):
        """
        Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        Examples:
            my_partial_object = minio.get_partial_object('foo', 'bar', 2, 4)

        :param bucketName: Bucket to retrieve object from
        :param objectName: Name of object to retrieve
        :param offset: Optional offset to retrieve bytes from. Must be >= 0
        :param length: Optional number of bytes to retrieve. Must be > 0
        :return: An iterable containing a stream of the data.
        """
        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        request_range = ''
        if offset is not 0 and length is not 0:
            request_range = str(offset) + '-' + str(offset + length - 1)
        if offset is not 0 and length is 0:
            request_range = str(offset) + '-'
        if offset is 0 and length is not 0:
            request_range = '0-' + str(length - 1)

        method = 'GET'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName)
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers,
                                      preload_content=False)

        if response.status != 206 and response.status != 200:
            parse_error(response, bucketName+'/'+objectName)

        return response.stream()

    def put_object(self, bucketName, objectName, data, length,
                   content_type='application/octet-stream'):
        """
        Add a new object to the cloud storage server.

        Examples:
         with open('hello.txt', 'rb') as data:
             minio.put_object('foo', 'bar', data, -1, 'text/plain')

        - For length lesser than 5MB put_object automatically does single Put operation.
        - For length equal to 0Bytes put_object automatically does single Put operation.
        - For length larger than 5MB put_object automatically does resumable multipart operation.
        - For length input as -1 put_object treats it as a stream and does multipart operation until
          input stream reaches EOF. Maximum object size that can be uploaded through this operation
          will be 5TB.

        :param bucketName: Bucket of new object.
        :param objectName: Name of new object.
        :param data: Contents to upload.
        :param length: Total length of object.
        :param content_type: mime type of object as a string.
        :return: None
        """
        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        if length > 5 * 1024 * 1024:
            return self._stream_put_object(bucketName, objectName, data, length, content_type)

        # reference 'file' for python 2.7 compatibility, RawIOBase for 3.X
        current_data = data.read(length)
        current_data_md5_base64 = encode_to_base64(get_md5(current_data))
        current_data_sha256_hex = encode_to_hex(get_sha256(current_data))
        return self._do_put_object(bucketName, objectName,
                                   io.BytesIO(current_data),
                                   current_data_md5_base64,
                                   current_data_sha256_hex,
                                   length, content_type)

    def list_objects(self, bucketName, prefix=None, recursive=False):
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

        :param bucketName: Bucket to list objects from
        :param prefix: String specifying objects returned must begin with
        :param recursive: If yes, returns all objects for a specified prefix
        :return: An iterator of objects in alphabetical order.
        """
        is_valid_bucket_name(bucketName)
        return ListObjectsIterator(self._http, self._endpoint_url, bucketName,
                                   prefix, recursive, self._access_key,
                                   self._secret_key, self._get_region(bucketName))

    def stat_object(self, bucketName, objectName):
        """
        Check if an object exists.

        :param bucketName: Bucket of object.
        :param objectName: Name of object
        :return: Object metadata if object exists
        """
        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        method = 'HEAD'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName)
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucketName+'/'+objectName)

        content_type = response.headers['content-type']
        etag = response.headers['etag'].replace('"', '')
        size = response.headers['content-length']
        last_modified = response.headers['last-modified']

        return Object(bucketName, objectName, content_type=content_type,
                      last_modified=last_modified, etag=etag, size=size)

    def remove_object(self, bucketName, objectName):
        """
        Remove an object from the bucket.

        :param bucketName: Bucket of object to remove
        :param objectName: Name of object to remove
        :return: None
        """
        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        method = 'DELETE'
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName)
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers)

        if response.status != 204:
            parse_error(response, bucketName+'/'+objectName)

    def list_incomplete_uploads(self, bucketName, prefix=None, recursive=False):
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
        is_valid_bucket_name(bucketName)
        delimiter = None
        if recursive == False:
            delimiter = '/'
        return ListIncompleteUploadsIterator(self._http, self._endpoint_url,
                                             bucketName, prefix,
                                             delimiter,
                                             access_key=self._access_key,
                                             secret_key=self._secret_key,
                                             region=self._get_region(bucketName))

    def remove_incomplete_upload(self, bucketName, objectName):
        """
        Remove all in-complete uploads for a given bucketName and objectName.

        :param bucketName: Bucket to drop incomplete uploads
        :param objectName: Name of object to remove incomplete uploads
        :return: None
        """
        is_valid_bucket_name(bucketName)
        is_non_empty_string(objectName)

        # check key
        uploads = ListIncompleteUploadsIterator(self._http, self._endpoint_url,
                                                bucketName, objectName,
                                                access_key=self._access_key,
                                                secret_key=self._secret_key)
        for upload in uploads:
            if objectName == upload.objectName:
                self._remove_incomplete_upload(bucketName, objectName, upload.upload_id)
                return

    # helper functions
    def _do_put_object(self, bucketName, objectName, data,
                       data_content_size, data_md5_base64,
                       data_sha256_hex, data_content_type='application/octet-stream',
                       upload_id='', part_number=0):

        method = 'PUT'
        region = self._get_region(bucketName)

        if upload_id.strip() and part_number is not 0:
            url = get_target_url(self._endpoint_url, bucketName=bucketName, objectName=objectName,
                                 query={'uploadId': upload_id, 'partNumber': part_number})
        else:
            url = get_target_url(self._endpoint_url, bucketName=bucketName, objectName=objectName)

        headers = {
            'Content-Length': data_content_size,
            'Content-Type': data_content_type,
            'Content-MD5': data_md5_base64
        }

        headers = sign_v4(method=method,
                          url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key,
                          content_sha256=data_sha256_hex)

        response = self._http.urlopen(method, url, headers=headers, body=data)
        if response.status != 200:
            parse_error(response, bucketName+'/'+objectName)

        return response.headers['etag'].replace('"', '')

    def _stream_put_object(self, bucketName, objectName, data,
                           data_content_size, data_content_type='application/octet-stream'):
        part_size = calculate_part_size(data_content_size)
        current_uploads = ListIncompleteUploadsIterator(self._http,
                                                        self._endpoint_url,
                                                        bucketName,
                                                        objectName,
                                                        access_key=self._access_key,
                                                        secret_key=self._secret_key)
        upload_id = None
        for upload in current_uploads:
            if objectName == upload.objectName:
                upload_id = upload.upload_id

        uploaded_parts = {}
        if upload_id is None:
            upload_id = self._new_multipart_upload(bucketName, objectName,
                                                   data_content_type)
        else:
            part_iter = ListUploadPartsIterator(self._http, self._endpoint_url,
                                                bucketName, objectName, upload_id,
                                                access_key=self._access_key,
                                                secret_key=self._secret_key,
                                                region=self._get_region(bucketName))
            for part in part_iter:
                uploaded_parts[part.part_number] = part

        total_uploaded = 0
        current_part_number = 1
        etags = []
        while total_uploaded < data_content_size:
            part = tempfile.NamedTemporaryFile(delete=True)
            part_metadata = parts_manager(data, part, hashlib.md5(), hashlib.sha256(), part_size)
            current_data_md5_hex = encode_to_hex(part_metadata.md5digest)
            current_data_md5_base64 = encode_to_base64(part_metadata.md5digest)
            current_data_sha256_hex = encode_to_hex(part_metadata.sha256digest)
            previously_uploaded_part = None
            if current_part_number in uploaded_parts:
                previously_uploaded_part = uploaded_parts[current_part_number]
            if previously_uploaded_part is None or \
               previously_uploaded_part.etag != current_data_md5_hex:
                ## Seek back to starting position.
                part.seek(0)
                etag = self._do_put_object(bucketName, objectName, part,
                                           part_metadata.size,
                                           current_data_md5_base64,
                                           current_data_sha256_hex,
                                           data_content_type=data_content_type,
                                           upload_id=upload_id,
                                           part_number=current_part_number)
            else:
                etag = previously_uploaded_part.etag
            etags.append(etag)
            total_uploaded += part_metadata.size
            current_part_number += 1

        self._complete_multipart_upload(bucketName, objectName, upload_id, etags)

    def _remove_incomplete_upload(self, bucketName, objectName, upload_id):
        method = 'DELETE'
        query = {
            'uploadId': upload_id
        }
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName,
                             query=query)
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 204:
            parse_error(response, bucketName+'/'+objectName)

    def _new_multipart_upload(self, bucketName, objectName, content_type):
        method = 'POST'
        query = {
            'uploads': None
        }

        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName, query=query)

        headers = { 'Content-Type': content_type }

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers, body=None)

        if response.status != 200:
            parse_error(response, bucketName+'/'+objectName)

        return parse_new_multipart_upload(response.data)

    def _complete_multipart_upload(self, bucketName, objectName, upload_id, etags):
        method = 'POST'
        query = {
            'uploadId': upload_id
        }
        region = self._get_region(bucketName)
        url = get_target_url(self._endpoint_url,
                             bucketName=bucketName,
                             objectName=objectName, query=query)
        headers = {}

        data = get_complete_multipart_upload(etags)
        data_md5_base64 = encode_to_base64(get_md5(data))
        data_sha256_hex = encode_to_hex(get_sha256(data))

        headers['Content-Length'] = len(data)
        headers['Content-Type'] = 'application/xml'
        headers['Content-MD5'] = data_md5_base64

        headers = sign_v4(method=method, url=url,
                          region=region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key,
                          content_sha256=data_sha256_hex)

        response = self._http.urlopen(method, url, headers=headers, body=data)

        if response.status != 200:
            parse_error(response, bucketName+'/'+objectName)

    def _set_region(self, bucketName, region=None):
        ## fetch bucket location only for Amazon S3.
        if 'amazonaws.com' in self._endpoint_url:
            if not region:
                region = self._get_bucket_location(bucketName)
            self._region_map[bucketName] = region
            return region
        return region

    def _get_region(self, bucketName):
        ## get proper location only for Amazon S3.
        if 'amazonaws.com' in self._endpoint_url:
            if self._region_map.has_key(bucketName):
                return self._region_map[bucketName]
            return self._set_region(bucketName)
        return 'us-east-1'

    def _get_bucket_location(self, bucketName):
        method = 'GET'
        url = self._endpoint_url + '/' + bucketName + '?location'
        headers = {}
        headers = sign_v4(method=method, url=url,
                          region='us-east-1',
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.urlopen(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, bucketName)

        location = parse_location_constraint(response.data)
        ## location is empty for 'US standard region'
        if not location:
            return 'us-east-1'
        ## location can be 'EU' convert it to meaningful 'eu-west-1'
        if location is 'EU':
            return 'eu-west-1'
        return location
