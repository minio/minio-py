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
import os
import hashlib

# Dependencies
import urllib3
import certifi
import pytz

# Internal imports
from . import __title__, __version__
from .compat import urlsplit, range
from .error import ResponseError, InvalidArgumentError, InvalidSizeError
from .definitions import Object, UploadPart
from .parsers import (parse_list_buckets,
                      parse_list_objects,
                      parse_list_parts,
                      parse_list_multipart_uploads,
                      parse_new_multipart_upload,
                      parse_location_constraint,
                      parse_multipart_upload_result)
from .helpers import (get_target_url, is_non_empty_string,
                      is_valid_endpoint,
                      get_sha256, encode_to_base64, get_md5,
                      optimal_part_info, encode_to_hex,
                      is_valid_bucket_name, parts_manager,
                      mkdir_p, dump_http)
from .helpers import (MAX_MULTIPART_OBJECT_SIZE,
                      MIN_OBJECT_SIZE)
from .signer import (sign_v4, presign_v4,
                     generate_credential_string,
                     post_presign_signature, _SIGN_V4_ALGORITHM)
from .xml_marshal import (xml_marshal_bucket_constraint,
                          xml_marshal_complete_multipart_upload)
from .limited_reader import LimitedReader

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

_SEVEN_DAYS_SECONDS = 604800  # 7days


class Minio(object):
    """
    Constructs a :class:`Minio <Minio>`.

    Examples:
        client = Minio('play.minio.io:9000')
        client = Minio('s3.amazonaws.com', 'ACCESS_KEY', 'SECRET_KEY')

    :param endpoint: Hostname of the cloud storage server.
    :param access_key: Access key to sign self._http.request with.
    :param secret_key: Secret key to sign self._http.request with.
    :param secure: Set this value if wish to make secure requests.
         Default is True.
    :return: :class:`Minio <Minio>` object
    """
    def __init__(self, endpoint, access_key=None,
                 secret_key=None, secure=True):
        # Validate endpoint.
        is_valid_endpoint(endpoint)

        # Default is a secured connection.
        endpoint_url = 'https://' + endpoint
        if not secure:
            endpoint_url = 'http://' + endpoint

        url_components = urlsplit(endpoint_url)
        self._region_map = dict()
        self._endpoint_url = url_components.geturl()
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = _DEFAULT_USER_AGENT
        self._trace_output_stream = None
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
            client.set_app_info('my_app', '1.0.2')

        :param app_name: application name.
        :param app_version: application version.
        """
        if not (app_name and app_version):
            raise ValueError('app_name and app_version cannot be empty.')

        app_info = _APP_INFO.format(app_name,
                                    app_version)
        self._user_agent = ' '.join([_DEFAULT_USER_AGENT, app_info])

    # enable HTTP trace.
    def trace_on(self, stream):
        """
        Enable http trace.

        :param output_stream: Stream where trace is written to.
        """
        if not stream:
            raise ValueError('Input stream for trace output is invalid.')
        # Save new output stream.
        self._trace_output_stream = stream

    # disable HTTP trace.
    def trace_off(self):
        """
        Disable HTTP trace.
        """
        self._trace_output_stream = None

    # Bucket level
    def make_bucket(self, bucket_name, location='us-east-1'):
        """
        Make a new bucket on the server.

        Optionally include Location.
           ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'sa-east-1',
            'cn-north-1']

        Examples:
            minio.make_bucket('foo')
            minio.make_bucket('foo', 'us-west-1')

        :param bucket_name: Bucket to create on server
        :param location: Location to create bucket on
        """
        is_valid_bucket_name(bucket_name)

        method = 'PUT'
        headers = {}

        # Set user agent once before the request.
        headers['User-Agent'] = self._user_agent

        content = ''
        if location and location != 'us-east-1':
            content = xml_marshal_bucket_constraint(location)
            headers['Content-Length'] = str(len(content))

        content_sha256_hex = encode_to_hex(get_sha256(content))
        if content.strip():
            content_md5_base64 = encode_to_base64(get_md5(content))
            headers['Content-MD5'] = content_md5_base64

        # In case of Amazon S3.  The make bucket issued on already
        # existing bucket would fail with 'AuthorizationMalformed'
        # error if virtual style is used. So we default to 'path
        # style' as that is the preferred method here. The final
        # location of the 'bucket' is provided through XML
        # LocationConstraint data with the request.
        # Construct target url.
        url = self._endpoint_url + '/' + bucket_name + '/'

        # Get signature headers if any.
        headers = sign_v4(method, url, 'us-east-1',
                          headers, self._access_key,
                          self._secret_key, content_sha256_hex)

        response = self._http.urlopen(method, url,
                                      body=content,
                                      headers=headers,
                                      preload_content=False)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.put(bucket_name)

        self._set_bucket_region(bucket_name, region=location)

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

        # Set user agent once before the request.
        headers['User-Agent'] = self._user_agent

        # default for all requests.
        region = 'us-east-1'

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers, self._access_key,
                          self._secret_key, None)

        response = self._http.urlopen(method, url,
                                      body=None,
                                      headers=headers,
                                      preload_content=False)

        if self._trace_output_stream:
            dump_http(method, url, headers, response,
                      self._trace_output_stream)

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
        headers = {}

        try:
            self._url_open(method, bucket_name=bucket_name,
                           headers=headers)
        # If the bucket has not been created yet, Minio will return a "NoSuchBucket" error.
        except ResponseError as e:
            if e.code == 'NoSuchBucket':
                return False
            raise

        return True

    def remove_bucket(self, bucket_name):
        """
        Remove a bucket.

        :param bucket_name: Bucket to remove
        """
        is_valid_bucket_name(bucket_name)

        method = 'DELETE'
        headers = {}

        self._url_open(method, bucket_name=bucket_name,
                       headers=headers)

        # Make sure to purge bucket_name from region cache.
        self._delete_bucket_region(bucket_name)

    def _get_upload_id(self, bucket_name, object_name, content_type):
        """
        Get previously uploaded upload id for object name or initiate a request to
        fetch a new upload id.

        :param bucket_name: Bucket name where the incomplete upload resides.
        :param object_name: Object name for which the upload id is requested for.
        :param content_type: Content type of the object.
        """
        recursive = True
        current_uploads = self._list_incomplete_uploads(bucket_name,
                                                        object_name,
                                                        recursive,
                                                        is_aggregate_size=False)
        upload_id = None
        # Default to '0'th epoch.
        latest_initiated_time = datetime.fromtimestamp(0, pytz.utc)
        for upload in current_uploads:
            if object_name == upload.object_name:
                latest_initiated_time = max((upload.initiated,
                                             latest_initiated_time))
                upload_id = upload.upload_id

        # If upload_id is None its a new multipart upload.
        if not upload_id:
            upload_id = self._new_multipart_upload(bucket_name,
                                                   object_name,
                                                   content_type)

        return upload_id

    def fput_object(self, bucket_name, object_name, file_path,
                    content_type='application/octet-stream'):
        """
        Add a new object to the cloud storage server.

        Examples:
            minio.fput_object('foo', 'bar', 'filepath', 'text/plain')

        :param bucket_name: Bucket to read object from.
        :param object_name: Name of the object to read.
        :param file_path: Local file path to be uploaded.
        :param content_type: Content type of the object.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        is_non_empty_string(file_path)

        # save file_size.
        file_size = os.stat(file_path).st_size

        if file_size > MAX_MULTIPART_OBJECT_SIZE:
            raise InvalidArgumentError('Input content size is bigger '
                                       ' than allowed maximum of 5TiB.')

        # Open file in 'read' mode.
        file_data = io.open(file_path, mode='rb')

        if file_size <= MIN_OBJECT_SIZE:
            data = file_data.read(file_size)
            md5_base64 = encode_to_base64(get_md5(data))
            sha256_hex = encode_to_hex(get_sha256(data))
            return self._do_put_object(bucket_name, object_name,
                                       io.BytesIO(data),
                                       md5_base64,
                                       sha256_hex,
                                       file_size,
                                       content_type=content_type)

        # Calculate optimal part info.
        total_parts_count, part_size, last_part_size = optimal_part_info(file_size)

        # get upload id.
        upload_id = self._get_upload_id(bucket_name, object_name, content_type)

        # Initialize variables
        uploaded_parts = {}
        total_uploaded = 0

        # Iter over the uploaded parts.
        parts_iter = self._list_object_parts(bucket_name,
                                             object_name,
                                             upload_id)

        for part in parts_iter:
            # Save uploaded parts for future verification.
            uploaded_parts[part.part_number] = part

        # Always start with first part number.
        for part_number in range(1, total_parts_count + 1):
            # Save the current part size that needs to be uploaded.
            current_part_size = part_size
            if part_number == total_parts_count:
                current_part_size = last_part_size

            # Save current offset as previous offset.
            prev_offset = file_data.seek(0, 1)

            # Calculate md5sum and sha256.
            md5hasher = hashlib.md5()
            sha256hasher = hashlib.sha256()
            total_read = 0

            # Save LimitedReader, read upto current_part_size for
            # md5sum and sha256 calculation.
            part = LimitedReader(file_data, current_part_size)
            while total_read < current_part_size:
                current_data = part.read() # Read in 64k chunks.
                if not current_data or len(current_data) == 0:
                    break
                md5hasher.update(current_data)
                sha256hasher.update(current_data)
                total_read = total_read + len(current_data)

            part_md5_hex = encode_to_hex(md5hasher.digest())
            # Verify if current part number has been already
            # uploaded. Verify if the size is same, further verify if
            # we have matching md5sum as well.
            if part_number in uploaded_parts:
                previous_part = uploaded_parts[part_number]
                if previous_part.size == current_part_size:
                    if previous_part.etag == part_md5_hex:
                        total_uploaded += previous_part.size
                        continue

            # Save hexlified sha256.
            part_sha256_hex = encode_to_hex(sha256hasher.digest())
            # Save base64 md5sum.
            part_md5_base64 = encode_to_base64(md5hasher.digest())

            # Seek back to previous offset position before checksum
            # calculation.
            file_data.seek(prev_offset, 0)

            # Create the LimitedReader again for the http reader.
            part = LimitedReader(file_data, current_part_size)

            # Initiate multipart put.
            etag = self._do_put_multipart_object(bucket_name, object_name,
                                                 part, part_md5_base64,
                                                 part_sha256_hex, total_read,
                                                 content_type, upload_id,
                                                 part_number)

            # Save etags.
            uploaded_parts[part_number] = UploadPart(bucket_name,
                                                     object_name,
                                                     upload_id,
                                                     part_number,
                                                     etag, None,
                                                     total_read)
            # Total uploaded.
            total_uploaded += total_read

        if total_uploaded != file_size:
            msg = 'Data uploaded {0} is not equal input size ' \
                  '{1}'.format(total_uploaded, file_size)
            raise InvalidSizeError(msg)

        # Complete all multipart transactions if possible.
        return self._complete_multipart_upload(bucket_name, object_name,
                                               upload_id, uploaded_parts)

    def fget_object(self, bucket_name, object_name, file_path):
        """
        Retrieves an object from a bucket and writes at file_path.

        Examples:
            minio.fget_object('foo', 'bar', 'localfile')

        :param bucket_name: Bucket to read object from.
        :param object_name: Name of the object to read.
        :param file_path: Local file path to save the object.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        stat = self.stat_object(bucket_name, object_name)

        file_is_dir = os.path.isdir(file_path)
        if file_is_dir:
            raise OSError("file is a directory.")

        # Create top level directory if needed.
        top_level_dir = os.path.dirname(file_path)
        if top_level_dir:
            mkdir_p(top_level_dir)

        # Write to a temporary file "file_path.part.minio-py" before saving.
        file_part_path = file_path + stat.etag + '.part.minio'

        # Open file in 'write+append' mode.
        with open(file_part_path, 'ab') as file_part_data:
            # Save current file_part statinfo.
            file_statinfo = os.stat(file_part_path)

            # Get partial object.
            response = self._get_partial_object(bucket_name, object_name,
                                                offset=file_statinfo.st_size,
                                                length=0)

            # Save content_size to verify if we wrote more data.
            content_size = int(response.headers['content-length'])

            # Save total_written.
            total_written = 0
            for data in response.stream(amt=1024*1024):
                file_part_data.write(data)
                total_written += len(data)

            # Verify if we wrote data properly.
            if total_written < content_size:
                msg = 'Data written {0} bytes is smaller than the' \
                      'specified size {1} bytes'.format(total_written,
                                                        content_size)
                raise InvalidSizeError(msg)

            if total_written > content_size:
                msg = 'Data written {0} bytes is in excess than the' \
                      'specified size {1} bytes'.format(total_written,
                                                        content_size)
                raise InvalidSizeError(msg)

        # Close the file.
        file_part_data.close()

        # Rename with destination file.
        os.rename(file_part_path, file_path)

    def get_object(self, bucket_name, object_name):
        """
        Retrieves an object from a bucket.

        Examples:
            my_object = minio.get_partial_object('foo', 'bar')

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

    def put_object(self, bucket_name, object_name, data, length,
                   content_type='application/octet-stream'):
        """
        Add a new object to the cloud storage server.

        NOTE: Maximum object size supported by this API is 5TiB.

        Examples:
         file_stat = os.stat('hello.txt')
         with open('hello.txt', 'rb') as data:
             minio.put_object('foo', 'bar', data, file_stat.size, 'text/plain')

        - For length lesser than 5MB put_object automatically
          does single Put operation.
        - For length larger than 5MB put_object automatically
          does resumable multipart operation.

        :param bucket_name: Bucket of new object.
        :param object_name: Name of new object.
        :param data: Contents to upload.
        :param length: Total length of object.
        :param content_type: mime type of object as a string.
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        if not callable(getattr(data, 'read')):
            raise ValueError('Invalid input data does not implement a callable read() method')

        if length > MAX_MULTIPART_OBJECT_SIZE:
            raise InvalidArgumentError('Input content size is bigger '
                                       ' than allowed maximum of 5TiB.')

        if length > MIN_OBJECT_SIZE:
            return self._stream_put_object(bucket_name, object_name,
                                           data, length,
                                           content_type=content_type)

        current_data = data.read(length)
        data_md5_base64 = encode_to_base64(get_md5(current_data))
        data_sha256_hex = encode_to_hex(get_sha256(current_data))
        return self._do_put_object(bucket_name, object_name,
                                   io.BytesIO(current_data),
                                   data_md5_base64,
                                   data_sha256_hex,
                                   length,
                                   content_type=content_type)

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

        method = 'GET'

        # Initialize query parameters.
        query = {}
        query['max-keys'] = 1000
        # Add if prefix present.
        if prefix:
            query['prefix'] = prefix

        # Delimited by default.
        query['delimiter'] = '/'
        if recursive:
            del query['delimiter']

        marker = ''
        is_truncated = True
        while is_truncated:
            if marker:
                query['marker'] = marker
            headers = {}
            response = self._url_open(method,
                                      bucket_name=bucket_name,
                                      query=query,
                                      headers=headers)
            objects, is_truncated, marker = parse_list_objects(response.data,
                                                               bucket_name=bucket_name)
            for obj in objects:
                yield obj

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
        headers = {}

        response = self._url_open(method, bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers)

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
        headers = {}

        # No reason to store successful response, for errors
        # relevant exceptions are thrown.
        self._url_open(method, bucket_name=bucket_name,
                       object_name=object_name,
                       headers=headers)

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
        :param prefix: String specifying objects returned must begin with.
        :param recursive: If yes, returns all incomplete uploads for
           a specified prefix.
        :return: An generator of incomplete uploads in alphabetical order.
        """
        is_valid_bucket_name(bucket_name)

        return self._list_incomplete_uploads(bucket_name, prefix, recursive)

    def _list_incomplete_uploads(self, bucket_name, prefix=None, recursive=False, is_aggregate_size=True):
        """
        List incomplete uploads list all previously uploaded incomplete multipart objects.

        :param bucket_name: Bucket name to list uploaded objects.
        :param prefix: String specifying objects returned must begin with.
        :param recursive: If yes, returns all incomplete objects for a specified prefix.
        :return: An generator of incomplete uploads in alphabetical order.
        """
        is_valid_bucket_name(bucket_name)

        method = 'GET'

        # Initialize query parameters.
        query = {
            'uploads': None
        }
        query['max-uploads'] = 1000
        if prefix:
            query['prefix'] = prefix

        # Default is delimited.
        query['delimiter'] = '/'
        if recursive:
            del query['delimiter']

        key_marker = ''
        upload_id_marker = ''
        is_truncated = True
        while is_truncated:
            headers = {}
            if key_marker:
                query['key-marker'] = key_marker
            if upload_id_marker:
                query['upload-id-marker'] = upload_id_marker

            response = self._url_open(method,
                                      bucket_name=bucket_name,
                                      query=query,
                                      headers=headers)
            uploads, is_truncated, key_marker, upload_id_marker = parse_list_multipart_uploads(response.data,
                                                                                               bucket_name=bucket_name)
            for upload in uploads:
                if is_aggregate_size:
                    upload.size = self._get_total_multipart_upload_size(upload.bucket_name,
                                                                        upload.object_name,
                                                                        upload.upload_id)
                yield upload

    def _get_total_multipart_upload_size(self, bucket_name, object_name, upload_id):
        """
        Get total multipart upload size.

        :param bucket_name: Bucket name to list parts for.
        :param object_name: Object name to list parts for.
        :param upload_id: Upload id of the previously uploaded object name.
        """
        total_part_size = 0
        for part in self._list_object_parts(bucket_name, object_name, upload_id):
            total_part_size += part.size

        return total_part_size

    def _list_object_parts(self, bucket_name, object_name, upload_id):
        """
        List all parts.

        :param bucket_name: Bucket name to list parts for.
        :param object_name: Object name to list parts for.
        :param upload_id: Upload id of the previously uploaded object name.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        is_non_empty_string(upload_id)

        method = 'GET'

        query = {
            'uploadId': upload_id
        }
        query['max-parts'] = 1000
        is_truncated = True

        part_number_marker = None
        while is_truncated:
            headers = {}
            if part_number_marker:
                query['part-number-marker'] = part_number_marker

            response = self._url_open(method,
                                      bucket_name=bucket_name,
                                      object_name=object_name,
                                      query=query,
                                      headers=headers)

            parts, is_truncated, part_number_marker = parse_list_parts(response.data,
                                                                       bucket_name=bucket_name,
                                                                       object_name=object_name,
                                                                       upload_id=upload_id)
            for part in parts:
                yield part

    def remove_incomplete_upload(self, bucket_name, object_name):
        """
        Remove all in-complete uploads for a given bucket_name and object_name.

        :param bucket_name: Bucket to drop incomplete uploads
        :param object_name: Name of object to remove incomplete uploads
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        recursive = True
        uploads = self._list_incomplete_uploads(bucket_name, object_name,
                                                recursive,
                                                is_aggregate_size=False)
        for upload in uploads:
            if object_name == upload.object_name:
                self._remove_incomplete_upload(bucket_name, object_name,
                                               upload.upload_id)
                return

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
        if expires.total_seconds() < 1 or \
           expires.total_seconds() > _SEVEN_DAYS_SECONDS:
            raise InvalidArgumentError('Expires param valid values'
                                       ' are between 1 secs to'
                                       ' {0} secs'.format(_SEVEN_DAYS_SECONDS))

        return self._presigned_get_partial_object(bucket_name,
                                                  object_name,
                                                  expires)

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
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        if expires.total_seconds() < 1 or \
           expires.total_seconds() > _SEVEN_DAYS_SECONDS:
            raise InvalidArgumentError('Expires param valid values'
                                       ' are between 1 secs to'
                                       ' {0} secs'.format(_SEVEN_DAYS_SECONDS))

        region = self._get_bucket_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name,
                             bucket_region=region)
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
        region = self._get_bucket_region(policy.form_data['bucket'])
        credential_string = generate_credential_string(self._access_key,
                                                       date, region)
        policy.policies.append(('eq', '$x-amz-date',
                                iso8601_date))
        policy.policies.append(('eq',
                                '$x-amz-algorithm',
                                _SIGN_V4_ALGORITHM))
        policy.policies.append(('eq',
                                '$x-amz-credential',
                                credential_string))

        policy_base64 = policy.base64()
        policy.form_data['policy'] = policy_base64
        policy.form_data['x-amz-algorithm'] = _SIGN_V4_ALGORITHM
        policy.form_data['x-amz-credential'] = credential_string
        policy.form_data['x-amz-date'] = iso8601_date
        signature = post_presign_signature(date, region,
                                           self._secret_key,
                                           policy_base64)
        policy.form_data['x-amz-signature'] = signature
        url_str = get_target_url(self._endpoint_url,
                                 bucket_name=policy.form_data['bucket'],
                                 bucket_region=region)
        return (url_str, policy.form_data)

    # All private functions below.
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
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

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
        headers = {}

        if request_range:
            headers['Range'] = 'bytes=' + request_range

        response = self._url_open(method,
                                  bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers)

        return response

    def _presigned_get_partial_object(self, bucket_name, object_name,
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

        region = self._get_bucket_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name,
                             bucket_region=region)
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

    def _do_put_multipart_object(self, bucket_name, object_name, data,
                                 md5_base64,
                                 sha256_hex,
                                 content_size,
                                 content_type='application/octet-stream',
                                 upload_id='', part_number=0):
        """
        Initiate a multipart PUT operation for a part number.

        :param bucket_name: Bucket name for the multipart request.
        :param object_name: Object name for the multipart request.
        :param data: Input data for the multipart request.
        :param md5_base64: Base64 md5 of data.
        :param sha256_hex: Hexadecimal sha256 of data.
        :param content_size: Input data size.
        :param content_type: Content type of multipart request.
        :param upload_id: Upload id of the multipart request.
        :param part_number: Part number of the data to be uploaded.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        if not callable(getattr(data, 'read')):
            raise ValueError('Invalid input data does not implement a callable read() method')

        method = 'PUT'
        headers = {
            'Content-Length': content_size,
            'Content-Type': content_type,
            'Content-MD5': md5_base64
        }

        response = self._url_open(method, bucket_name=bucket_name,
                                  object_name=object_name,
                                  query={'uploadId': upload_id,
                                         'partNumber': part_number},
                                  headers=headers,
                                  body=data,
                                  content_sha256=sha256_hex)

        return response.headers['etag'].replace('"', '')

    def _do_put_object(self, bucket_name, object_name, data,
                       md5_base64,
                       sha256_hex,
                       content_size,
                       content_type='application/octet-stream'):
        """
        Initiate a single PUT operation.

        :param bucket_name: Bucket name for the put request.
        :param object_name: Object name for the put request.
        :param data: Input data for the put request.
        :param md5_base64: Base64 md5 of data.
        :param sha256_hex: Hexadecimal sha256 of data.
        :param content_size: Input data size.
        :param content_type: Content type of put request.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        if not callable(getattr(data, 'read')):
            raise ValueError('Invalid input data does not implement a callable read() method')

        method = 'PUT'
        headers = {
            'Content-Length': content_size,
            'Content-Type': content_type,
            'Content-MD5': md5_base64
        }

        response = self._url_open(method, bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers,
                                  body=data,
                                  content_sha256=sha256_hex)

        etag = response.headers['etag']
        # Strip off quotes from begining and the end.
        if etag.startswith('"') and etag.endswith('"'):
            etag = etag[len('"'):]
            etag = etag[:-len('"')]

        # Returns here.
        return etag

    def _stream_put_object(self, bucket_name, object_name,
                           data, content_size,
                           content_type='application/octet-stream'):
        """
        Streaming multipart upload operation.

        :param bucket_name: Bucket name of the multipart upload.
        :param object_name: Object name of the multipart upload.
        :param content_size: Total size of the content to be uploaded.
        :param content_type: Content type of of the multipart upload.
           Defaults to 'application/octet-stream'.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        if not callable(getattr(data, 'read')):
            raise ValueError('Invalid input data does not implement a callable read() method')

        # get upload id.
        upload_id = self._get_upload_id(bucket_name, object_name, content_type)

        # Initialize variables
        uploaded_parts = {}
        total_uploaded = 0

        # Calculate optimal part info.
        total_parts_count, part_size, last_part_size = optimal_part_info(content_size)

        # Iter over the uploaded parts.
        parts_iter = self._list_object_parts(bucket_name,
                                             object_name,
                                             upload_id)

        for part in parts_iter:
            # Save uploaded parts for future verification.
            uploaded_parts[part.part_number] = part

        # Generate new parts and upload <= current_part_size until
        # part_number reaches total_parts_count calculated for the
        # given size. Additionally part_manager() also provides
        # md5digest and sha256digest for the partitioned data.
        for part_number in range(1, total_parts_count + 1):
            current_part_size = part_size
            if part_number == total_parts_count:
                current_part_size = last_part_size
            part_metadata = parts_manager(data, current_part_size)
            md5_hex = encode_to_hex(part_metadata.md5digest)
            # Verify if part number has been already uploaded.
            # Further verify if we have matching md5sum as well.
            if part_number in uploaded_parts:
                previous_part = uploaded_parts[part_number]
                if previous_part.size == current_part_size:
                    if previous_part.etag == md5_hex:
                        total_uploaded += previous_part.size
                        continue

            md5_base64 = encode_to_base64(part_metadata.md5digest)
            sha256_hex = encode_to_hex(part_metadata.sha256digest)
            # Seek back to starting position.
            part_metadata.data.seek(0)
            etag = self._do_put_multipart_object(bucket_name,
                                                 object_name,
                                                 part_metadata.data,
                                                 md5_base64,
                                                 sha256_hex,
                                                 part_metadata.size,
                                                 content_type,
                                                 upload_id,
                                                 part_number)
            # Save etags.
            uploaded_parts[part_number] = UploadPart(bucket_name,
                                                     object_name,
                                                     upload_id,
                                                     part_number,
                                                     etag,
                                                     None,
                                                     part_metadata.size)

            total_uploaded += part_metadata.size

        if total_uploaded != content_size:
            msg = 'Data uploaded {0} is not equal input size ' \
                  '{1}'.format(total_uploaded, content_size)
            raise InvalidSizeError(msg)

        # Complete all multipart transactions if possible.
        return self._complete_multipart_upload(bucket_name, object_name,
                                               upload_id, uploaded_parts)

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
        headers = {}

        # No reason to store successful response, for errors
        # relevant exceptions are thrown.
        self._url_open(method, bucket_name=bucket_name,
                       object_name=object_name, query=query,
                       headers=headers)

    def _new_multipart_upload(self, bucket_name, object_name,
                              content_type='application/octet-stream'):
        """
        Initialize new multipart upload request.

        :param bucket_name: Bucket name of the new multipart request.
        :param object_name: Object name of the new multipart request.
        :param content_type: Content type of the new object.
        :return: Returns an upload id.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        method = 'POST'
        query = {
            'uploads': None
        }
        headers = {'Content-Type': content_type}

        response = self._url_open(method, bucket_name=bucket_name,
                                  object_name=object_name, query=query,
                                  headers=headers)

        return parse_new_multipart_upload(response.data)

    def _complete_multipart_upload(self, bucket_name, object_name,
                                   upload_id, uploaded_parts):
        """
        Complete an active multipart upload request.

        :param bucket_name: Bucket name of the multipart request.
        :param object_name: Object name of the multipart request.
        :param upload_id: Upload id of the active multipart request.
        :param uploaded_parts: Key, Value dictionary of uploaded parts.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        is_non_empty_string(upload_id)

        method = 'POST'
        query = {
            'uploadId': upload_id
        }
        headers = {}

        data = xml_marshal_complete_multipart_upload(uploaded_parts)
        md5_base64 = encode_to_base64(get_md5(data))
        sha256_hex = encode_to_hex(get_sha256(data))

        headers['Content-Length'] = len(data)
        headers['Content-Type'] = 'application/xml'
        headers['Content-MD5'] = md5_base64

        response = self._url_open(method, bucket_name=bucket_name,
                                  object_name=object_name, query=query,
                                  headers=headers, body=data,
                                  content_sha256=sha256_hex)

        return parse_multipart_upload_result(response.data)

    def _delete_bucket_region(self, bucket_name):
        """
        Delete a bucket from bucket region cache.

        :param bucket_name: Bucket name to be removed from cache.
        """

        # Handles if bucket doesn't exist as well.
        self._region_map.pop(bucket_name, None)

    def _set_bucket_region(self, bucket_name, region='us-east-1'):
        """
        Sets a bucket region into bucket region cache.

        :param bucket_name: Bucket name for which region is set.
        :param region: Region of the bucket name to set.
        """
        self._region_map[bucket_name] = region

    def _get_bucket_region(self, bucket_name):
        """
        Get region based on the bucket name.

        :param bucket_name: Bucket name for which region will be fetched.
        :return: Region of bucket name.
        """
        # get bucket location for Amazon S3.
        region = 'us-east-1' # default to US standard.
        if bucket_name in self._region_map:
            region = self._region_map[bucket_name]
        else:
            region = self._get_bucket_location(bucket_name)
            self._region_map[bucket_name] = region
        return region

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

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers, self._access_key,
                          self._secret_key, None)

        response = self._http.urlopen(method, url,
                                      body=None,
                                      headers=headers,
                                      preload_content=False)

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

    def _url_open(self, method, bucket_name=None, object_name=None,
                  query=None, body=None, headers=None, content_sha256=None):
        """
        Open a url wrapper around signature version '4'
           and :meth:`urllib3.PoolManager.urlopen`
        """
        # Set user agent once before the request.
        headers['User-Agent'] = self._user_agent

        # Get bucket region.
        region = self._get_bucket_region(bucket_name)

        # Construct target url.
        url = get_target_url(self._endpoint_url, bucket_name=bucket_name,
                             object_name=object_name, bucket_region=region,
                             query=query)

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers, self._access_key,
                          self._secret_key, content_sha256)

        response = self._http.urlopen(method, url,
                                      body=body,
                                      headers=headers,
                                      preload_content=False)

        if self._trace_output_stream:
            dump_http(method, url, headers, response,
                      self._trace_output_stream)

        if response.status != 200 and \
           response.status != 204 and response.status != 206:
            # Upon any response error invalidate the region cache
            # proactively for the bucket name.
            self._delete_bucket_region(bucket_name)

            # Populate response_error with error response.
            response_error = ResponseError(response)
            if method == 'HEAD':
                raise response_error.head(bucket_name, object_name)
            elif method == 'GET':
                raise response_error.get(bucket_name, object_name)
            elif method == 'POST':
                raise response_error.post(bucket_name, object_name)
            elif method == 'PUT':
                raise response_error.put(bucket_name, object_name)
            elif method == 'DELETE':
                raise response_error.delete(bucket_name, object_name)
            else:
                raise ValueError('Unsupported method returned'
                                 ' error: {0}'.format(response.status))

        return response
