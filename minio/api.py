# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016 Minio, Inc.
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

:copyright: (c) 2015, 2016 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

# Standard python packages
from __future__ import absolute_import
import platform

from time import mktime, strptime
from datetime import datetime, timedelta

import io
import json
import os
import itertools
import codecs

# Dependencies
import urllib3
import certifi

# Internal imports
from . import __title__, __version__
from .compat import (urlsplit, queryencode,
                     range, basestring)
from .error import (KnownResponseError, ResponseError, NoSuchBucket,
                    InvalidArgumentError, InvalidSizeError, NoSuchBucketPolicy)
from .definitions import Object, UploadPart
from .parsers import (parse_list_buckets,
                      parse_list_objects,
                      parse_list_objects_v2,
                      parse_list_parts,
                      parse_copy_object,
                      parse_list_multipart_uploads,
                      parse_new_multipart_upload,
                      parse_location_constraint,
                      parse_multipart_upload_result,
                      parse_get_bucket_notification,
                      parse_multi_object_delete_response)
from .helpers import (get_target_url, is_non_empty_string,
                      is_valid_endpoint,
                      get_sha256_hexdigest, get_md5_base64digest, Hasher,
                      optimal_part_info,
                      is_valid_bucket_name, PartMetadata, parts_manager,
                      is_valid_bucket_notification_config,
                      mkdir_p, dump_http)
from .helpers import (MAX_MULTIPART_OBJECT_SIZE,
                      MIN_OBJECT_SIZE)
from .signer import (sign_v4, presign_v4,
                     generate_credential_string,
                     post_presign_signature, _SIGN_V4_ALGORITHM)
from .xml_marshal import (xml_marshal_bucket_constraint,
                          xml_marshal_complete_multipart_upload,
                          xml_marshal_bucket_notifications,
                          xml_marshal_delete_objects)
from .limited_reader import LimitedReader
from . import policy
from .fold_case_dict import FoldCaseDict

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

        # To override auto bucket location discovery.
        client = Minio('play.minio.io:9000', 'ACCESS_KEY', 'SECRET_KEY',
                       region='us-east-1')

    :param endpoint: Hostname of the cloud storage server.
    :param access_key: Access key to sign self._http.request with.
    :param secret_key: Secret key to sign self._http.request with.
    :param secure: Set this value if wish to make secure requests.
         Default is True.
    :param region: Set this value to override automatic bucket
         location discovery.
    :param timeout: Set this value to control how long requests
         are allowed to run before being aborted.
    :return: :class:`Minio <Minio>` object
    """

    def __init__(self, endpoint, access_key=None,
                 secret_key=None, secure=True,
                 region=None,
                 timeout=None,
                 certificate_bundle=certifi.where()):

        # Validate endpoint.
        is_valid_endpoint(endpoint)

        # Default is a secured connection.
        endpoint_url = 'https://' + endpoint
        if not secure:
            endpoint_url = 'http://' + endpoint

        # Parse url endpoints.
        url_components = urlsplit(endpoint_url)
        self._region = region
        self._region_map = dict()
        self._endpoint_url = url_components.geturl()
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = _DEFAULT_USER_AGENT
        self._trace_output_stream = None

        self._conn_timeout = urllib3.Timeout.DEFAULT_TIMEOUT if not timeout \
                             else urllib3.Timeout(timeout)

        self._http = urllib3.PoolManager(
            timeout=self._conn_timeout,
            cert_reqs='CERT_REQUIRED',
            ca_certs=certificate_bundle,
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
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

        ## Region already set in constructor, validate if
        ## caller requested bucket location is same.
        if self._region:
            if self._region != location:
                raise InvalidArgumentError("Configured region {0}, requested"
                                           " {1}".format(self._region,
                                                         location))

        method = 'PUT'
        # Set user agent once before the request.
        headers = {'User-Agent': self._user_agent}

        content = None
        if location and location != 'us-east-1':
            content = xml_marshal_bucket_constraint(location)
            headers['Content-Length'] = str(len(content))

        content_sha256_hex = get_sha256_hexdigest(content)
        if content:
            headers['Content-Md5'] = get_md5_base64digest(content)

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
                                      headers=headers)

        if response.status != 200:
            raise ResponseError(response, method, bucket_name).get_exception()

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
        url = get_target_url(self._endpoint_url)

        # Set user agent once before the request.
        headers = {'User-Agent': self._user_agent}

        # default for all requests.
        region = 'us-east-1'

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers, self._access_key,
                          self._secret_key, None)

        response = self._http.urlopen(method, url,
                                      body=None,
                                      headers=headers)

        if self._trace_output_stream:
            dump_http(method, url, headers, response,
                      self._trace_output_stream)

        if response.status != 200:
            raise ResponseError(response, method).get_exception()

        return parse_list_buckets(response.data)

    def bucket_exists(self, bucket_name):
        """
        Check if the bucket exists and if the user has access to it.

        :param bucket_name: To test the existence and user access.
        :return: True on success.
        """
        is_valid_bucket_name(bucket_name)

        try:
            self._url_open('HEAD', bucket_name=bucket_name)
        # If the bucket has not been created yet, Minio will return a "NoSuchBucket" error.
        except NoSuchBucket as e:
            return False
        except ResponseError as e:
            raise
        return True

    def remove_bucket(self, bucket_name):
        """
        Remove a bucket.

        :param bucket_name: Bucket to remove
        """
        is_valid_bucket_name(bucket_name)
        self._url_open('DELETE', bucket_name=bucket_name)

        # Make sure to purge bucket_name from region cache.
        self._delete_bucket_region(bucket_name)

    def _get_bucket_policy(self, bucket_name):
        policy_dict = {}
        try:
            response = self._url_open("GET",
                                      bucket_name=bucket_name,
                                      query={"policy": ""})
        except NoSuchBucketPolicy as e:
            return None
        except ResponseError as e:
            raise

        data = response.data
        if isinstance(data, bytes) and isinstance(data, str):  # Python 2
            policy_dict = json.loads(data.decode('utf-8'))
        elif isinstance(data, str):  # Python 3
            policy_dict = json.loads(data)
        else:
            policy_dict = json.loads(str(data, 'utf-8'))

        return policy_dict

    def get_bucket_policy(self, bucket_name, prefix=""):
        """
        Get bucket policy of given bucket name.

        :param bucket_name: Bucket name.
        :param prefix: Object prefix.
        """
        is_valid_bucket_name(bucket_name)

        policy_dict = self._get_bucket_policy(bucket_name)
        if not policy_dict:
            return policy.Policy.NONE

        # Normalize statements.
        statements = []
        policy._append_statements(statements, policy_dict.get('Statement', []))

        return policy.get_policy(statements, bucket_name, prefix)

    def set_bucket_policy(self, bucket_name, prefix, policy_access):
        """
        Set bucket policy of given bucket name and object prefix.

        :param bucket_name: Bucket name.
        :param prefix: Object prefix.
        """
        is_valid_bucket_name(bucket_name)

        policy_dict = self._get_bucket_policy(bucket_name)
        if policy_access == policy.Policy.NONE and not policy_dict:
            return

        if not policy_dict:
            policy_dict = {'Statement': [],
                           "Version": "2012-10-17"}

        # Normalize statements.
        statements = []
        policy._append_statements(statements, policy_dict['Statement'])

        statements = policy.set_policy(statements, policy_access,
                                       bucket_name, prefix)
        if not statements:
            self._url_open("DELETE",
                           bucket_name=bucket_name,
                           query={"policy": ""})
        else:
            policy_dict['Statement'] = statements
            content = json.dumps(policy_dict)

            headers = {
                'Content-Length': str(len(content)),
                'Content-Md5': get_md5_base64digest(content)
            }
            content_sha256_hex = get_sha256_hexdigest(content)

            self._url_open("PUT",
                           bucket_name=bucket_name,
                           query={"policy": ""},
                           headers=headers,
                           body=content,
                           content_sha256=content_sha256_hex)

    def get_bucket_notification(self, bucket_name):
        """
        Get notifications configured for the given bucket.

        :param bucket_name: Bucket name.
        """
        is_valid_bucket_name(bucket_name)

        response = self._url_open(
            "GET",
            bucket_name=bucket_name,
            query={"notification": ""},
        )
        data = response.read().decode('utf-8')
        return parse_get_bucket_notification(data)

    def set_bucket_notification(self, bucket_name, notifications):
        """
        Set the given notifications on the bucket.

        :param bucket_name: Bucket name.
        :param notifications: Notifications structure
        """
        is_valid_bucket_name(bucket_name)
        is_valid_bucket_notification_config(notifications)

        content = xml_marshal_bucket_notifications(notifications)
        headers = {
            'Content-Length': str(len(content)),
            'Content-Md5': get_md5_base64digest(content)
        }
        content_sha256_hex = get_sha256_hexdigest(content)
        self._url_open(
            'PUT',
            bucket_name=bucket_name,
            query={"notification": ""},
            headers=headers,
            body=content,
            content_sha256=content_sha256_hex
        )

    def remove_all_bucket_notification(self, bucket_name):
        """
        Removes all bucket notification configs configured
        previously, this call disable event notifications
        on a bucket. This operation cannot be undone, to
        set notifications again you should use
        ``set_bucket_notification``

        :param bucket_name: Bucket name.
        """
        is_valid_bucket_name(bucket_name)

        content_bytes = xml_marshal_bucket_notifications({})
        headers = {
            'Content-Length': str(len(content_bytes)),
            'Content-Md5': get_md5_base64digest(content_bytes)
        }
        content_sha256_hex = get_sha256_hexdigest(content_bytes)
        self._url_open(
            'PUT',
            bucket_name=bucket_name,
            query={"notification": ""},
            headers=headers,
            body=content_bytes,
            content_sha256=content_sha256_hex
        )

    def listen_bucket_notification(self, bucket_name, prefix='', suffix='',
                                   events=['s3:ObjectCreated:*',
                                           's3:ObjectRemoved:*',
                                           's3:ObjectAccessed:*']):
        """
        Yeilds new event notifications on a bucket, caller should iterate
        to read new notifications.

        NOTE: Notification is retried in case of `SyntaxError` otherwise
        the function raises an exception.

        :param bucket_name: Bucket name to listen event notifications from.
        :param prefix: Object key prefix to filter notifications for.
        :param suffix: Object key suffix to filter notifications for.
        :param events: Enables notifications for specific event types.
             of events.
        """
        is_valid_bucket_name(bucket_name)

        url_components = urlsplit(self._endpoint_url)
        if url_components.hostname == 's3.amazonaws.com':
            raise InvalidArgumentError(
                'Listening for event notifications on a bucket is a Minio '
                'specific extension to bucket notification API. It is not '
                'supported by Amazon S3')

        query = {
            'prefix': prefix,
            'suffix': suffix,
            'events': events,
        }
        while True:
            response = self._url_open('GET', bucket_name=bucket_name,
                                      query=query, preload_content=False)
            try:
                for line in response.stream():
                    event = json.loads(line)
                    if event['Records'] is not None:
                        yield event
            except SyntaxError:
                response.close()
                continue

    def _get_upload_id(self, bucket_name, object_name, metadata=None):
        """
        Get previously uploaded upload id for object name or initiate a request
        to fetch a new upload id.

        :param bucket_name: Bucket name where the incomplete upload resides.
        :param object_name: Object name for which upload id is requested.
        :param metadata: Additional metadata headers for new multipart upload.
        """
        recursive = True
        current_uploads = self._list_incomplete_uploads(bucket_name,
                                                        object_name,
                                                        recursive,
                                                        is_aggregate_size=False)
        matching_uploads = [upload
                            for upload in current_uploads
                            if object_name == upload.object_name]

        # If no matching uploads its a new multipart upload.
        if not len(matching_uploads):
            upload_id = self._new_multipart_upload(bucket_name,
                                                   object_name,
                                                   metadata)
        else:
            incomplete_upload = max(matching_uploads, key=lambda x: x.initiated)
            upload_id = incomplete_upload.upload_id

        return upload_id

    def fput_object(self, bucket_name, object_name, file_path,
                    content_type='application/octet-stream',
                    metadata=None):
        """
        Add a new object to the cloud storage server.

        Examples:
            minio.fput_object('foo', 'bar', 'filepath', 'text/plain')

        :param bucket_name: Bucket to read object from.
        :param object_name: Name of the object to read.
        :param file_path: Local file path to be uploaded.
        :param content_type: Content type of the object.
        :param metadata: Any additional metadata to be uploaded along
            with your PUT request.
        :return: etag
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
            return self._do_put_object(bucket_name, object_name,
                                       file_data.read(file_size),
                                       metadata=metadata)

        if not metadata:
            metadata = {}

        metadata['Content-Type'] = 'application/octet-stream' if \
            not content_type else content_type

        # Calculate optimal part info.
        total_parts_count, part_size, last_part_size = optimal_part_info(
            file_size)

        # get upload id.
        upload_id = self._get_upload_id(bucket_name, object_name, metadata)

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
            md5hasher = Hasher.md5()
            sha256hasher = Hasher.sha256()
            total_read = 0

            # Save LimitedReader, read upto current_part_size for
            # md5sum and sha256 calculation.
            part = LimitedReader(file_data, current_part_size)
            while total_read < current_part_size:
                current_data = part.read()  # Read in 64k chunks.
                if not current_data or len(current_data) == 0:
                    break
                md5hasher.update(current_data)
                sha256hasher.update(current_data)
                total_read += len(current_data)

            part_md5_hex = md5hasher.hexdigest()
            # Verify if current part number has been already
            # uploaded. Verify if the size is same, further verify if
            # we have matching md5sum as well.
            if part_number in uploaded_parts:
                previous_part = uploaded_parts[part_number]
                if previous_part.size == current_part_size:
                    if previous_part.etag == part_md5_hex:
                        total_uploaded += previous_part.size
                        continue

            # Seek back to previous offset position before checksum
            # calculation.
            file_data.seek(prev_offset, 0)

            # Create the LimitedReader again for the http reader.
            part = LimitedReader(file_data, current_part_size)
            part_metadata = PartMetadata(part, md5hasher.hexdigest(), sha256hasher.hexdigest(),
                                         current_part_size)
            # Initiate multipart put.
            etag = self._do_put_multipart_object(bucket_name, object_name,
                                                 part_metadata,
                                                 upload_id,
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
        mpart_result = self._complete_multipart_upload(bucket_name,
                                                       object_name,
                                                       upload_id,
                                                       uploaded_parts)
        # Return etag here.
        return mpart_result.etag

    def fget_object(self, bucket_name, object_name, file_path, request_headers=None):
        """
        Retrieves an object from a bucket and writes at file_path.

        Examples:
            minio.fget_object('foo', 'bar', 'localfile')

        :param bucket_name: Bucket to read object from.
        :param object_name: Name of the object to read.
        :param file_path: Local file path to save the object.
        :param request_headers: Any additional headers to be added with GET request.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        stat = self.stat_object(bucket_name, object_name)

        if os.path.isdir(file_path):
            raise OSError("file is a directory.")

        # Create top level directory if needed.
        top_level_dir = os.path.dirname(file_path)
        if top_level_dir:
            mkdir_p(top_level_dir)

        # Write to a temporary file "file_path.part.minio" before saving.
        file_part_path = file_path + stat.etag + '.part.minio'

        # Open file in 'write+append' mode.
        with open(file_part_path, 'ab') as file_part_data:
            # Save current file_part statinfo.
            file_statinfo = os.stat(file_part_path)

            # Get partial object.
            response = self._get_partial_object(bucket_name, object_name,
                                                offset=file_statinfo.st_size,
                                                length=0,
                                                request_headers=request_headers)

            # Save content_size to verify if we wrote more data.
            content_size = int(response.headers['content-length'])

            # Save total_written.
            total_written = 0
            for data in response.stream(amt=1024 * 1024):
                file_part_data.write(data)
                total_written += len(data)

            # Release the connection from the response at this point.
            response.release_conn()

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

        # Rename with destination file.
        os.rename(file_part_path, file_path)

        # Return the stat
        return stat

    def get_object(self, bucket_name, object_name, request_headers=None):
        """
        Retrieves an object from a bucket.

        This function returns an object that contains an open network
        connection to enable incremental consumption of the
        response. To re-use the connection (if desired) on subsequent
        requests, the user needs to call `release_conn()` on the
        returned object after processing.

        Examples:
            my_object = minio.get_partial_object('foo', 'bar')

        :param bucket_name: Bucket to read object from
        :param object_name: Name of object to read
        :param request_headers: Any additional headers to be added with GET request.
        :return: :class:`urllib3.response.HTTPResponse` object.

        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        return self._get_partial_object(bucket_name,
                                        object_name,
                                        request_headers=request_headers)

    def get_partial_object(self, bucket_name, object_name, offset=0, length=0, request_headers=None):
        """
        Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        This function returns an object that contains an open network
        connection to enable incremental consumption of the
        response. To re-use the connection (if desired) on subsequent
        requests, the user needs to call `release_conn()` on the
        returned object after processing.

        Examples:
            partial_object = minio.get_partial_object('foo', 'bar', 2, 4)

        :param bucket_name: Bucket to retrieve object from
        :param object_name: Name of object to retrieve
        :param offset: Optional offset to retrieve bytes from.
           Must be >= 0.
        :param length: Optional number of bytes to retrieve.
           Must be an integer.
        :param request_headers: Any additional headers to be added with GET request.
        :return: :class:`urllib3.response.HTTPResponse` object.

        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        return self._get_partial_object(bucket_name,
                                        object_name,
                                        offset, length,
                                        request_headers=request_headers)

    def copy_object(self, bucket_name, object_name, object_source,
                    conditions=None):
        """
        Copy a source object on object storage server to a new object.

        NOTE: Maximum object size supported by this API is 5GB.

        Examples:

        :param bucket_name: Bucket of new object.
        :param object_name: Name of new object.
        :param object_source: Source object to be copied.
        :param conditions: :class:`CopyConditions` object. Collection of
        supported CopyObject conditions.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        is_non_empty_string(object_source)

        headers = {}
        if conditions:
            headers = {k: v for k, v in conditions.items()}

        headers['X-Amz-Copy-Source'] = queryencode(object_source)
        response = self._url_open('PUT',
                                  bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers)

        return parse_copy_object(bucket_name, object_name, response.data)

    def put_object(self, bucket_name, object_name, data, length,
                   content_type='application/octet-stream',
                   metadata=None):
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
        :param metadata: Any additional metadata to be uploaded along
            with your PUT request.
        :return: etag
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        if not callable(getattr(data, 'read')):
            raise ValueError(
                'Invalid input data does not implement a callable read() method')

        if length > MAX_MULTIPART_OBJECT_SIZE:
            raise InvalidArgumentError('Input content size is bigger '
                                       ' than allowed maximum of 5TiB.')
        if not metadata:
            metadata = {}

        metadata['Content-Type'] = 'application/octet-stream' if \
            not content_type else content_type

        if length > MIN_OBJECT_SIZE:
            return self._stream_put_object(bucket_name, object_name,
                                           data, length, metadata=metadata)

        current_data = data.read(length)
        if len(current_data) != length:
            raise InvalidArgumentError(
                'Could not read {} bytes from data to upload'.format(length)
            )
        return self._do_put_object(bucket_name, object_name,
                                   current_data, metadata=metadata)

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
        query = {
            'max-keys': '1000'
        }

        # Add if prefix present.
        if prefix:
            query['prefix'] = prefix

        # Delimited by default.
        if not recursive:
            query['delimiter'] = '/'

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

    def list_objects_v2(self, bucket_name, prefix=None, recursive=False):
        """
        List objects in the given bucket using the List objects V2 API.

        Examples:
            objects = minio.list_objects_v2('foo')
            for current_object in objects:
                print(current_object)
            # hello
            # hello/
            # hello/
            # world/

            objects = minio.list_objects_v2('foo', prefix='hello/')
            for current_object in objects:
                print(current_object)
            # hello/world/

            objects = minio.list_objects_v2('foo', recursive=True)
            for current_object in objects:
                print(current_object)
            # hello/world/1
            # world/world/2
            # ...

            objects = minio.list_objects_v2('foo', prefix='hello/',
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

        # Initialize query parameters.
        query = {
            'list-type': '2'
        }
        # Add if prefix present.
        if prefix:
            query['prefix'] = prefix

        # Delimited by default.
        if not recursive:
            query['delimiter'] = '/'

        continuation_token = None
        is_truncated = True
        while is_truncated:
            if continuation_token is not None:
                query['continuation-token'] = continuation_token
            response = self._url_open(method='GET',
                                      bucket_name=bucket_name,
                                      query=query)
            objects, is_truncated, continuation_token = parse_list_objects_v2(
                response.data, bucket_name=bucket_name
            )

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

        response = self._url_open('HEAD', bucket_name=bucket_name,
                                  object_name=object_name)

        etag = response.headers.get('etag', '').replace('"', '')
        size = int(response.headers.get('content-length', '0'))
        content_type = response.headers.get('content-type', '')
        last_modified = response.headers.get('last-modified')

        ## Supported headers for object.
        supported_headers = [
            'cache-control',
            'content-encoding',
            'content-disposition',
            ## Add more supported headers here.
        ]

        ## Capture only custom metadata.
        custom_metadata = dict()
        for k in response.headers:
            if k in supported_headers or k.lower().startswith('x-amz-meta-'):
                custom_metadata[k] = response.headers.get(k)

        if last_modified:
            http_time_format = "%a, %d %b %Y %H:%M:%S GMT"
            last_modified = mktime(strptime(last_modified, http_time_format))
        return Object(bucket_name, object_name, last_modified, etag, size,
                      content_type=content_type, metadata=custom_metadata)

    def remove_object(self, bucket_name, object_name):
        """
        Remove an object from the bucket.

        :param bucket_name: Bucket of object to remove
        :param object_name: Name of object to remove
        :return: None
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        # No reason to store successful response, for errors
        # relevant exceptions are thrown.
        self._url_open('DELETE', bucket_name=bucket_name,
                       object_name=object_name)

    def _process_remove_objects_batch(self, bucket_name, objects_batch):
        """
        Requester and response parser for remove_objects
        """
        # assemble request content for objects_batch
        content = xml_marshal_delete_objects(objects_batch)

        # compute headers
        headers = {
            'Content-Md5': get_md5_base64digest(content),
            'Content-Length': len(content)
        }
        query = {'delete': ''}
        content_sha256_hex = get_sha256_hexdigest(content)

        # send multi-object delete request
        response = self._url_open(
            'POST', bucket_name=bucket_name,
            headers=headers, body=content,
            query=query, content_sha256=content_sha256_hex,
        )

        # parse response to find delete errors
        return parse_multi_object_delete_response(response.data)

    def remove_objects(self, bucket_name, objects_iter):
        """
        Removes multiple objects from a bucket.

        :param bucket_name: Bucket from which to remove objects

        :param objects_iter: A list, tuple or iterator that provides
        objects names to delete.

        :return: An iterator of MultiDeleteError instances for each
        object that had a delete error.

        """
        is_valid_bucket_name(bucket_name)
        if isinstance(objects_iter, basestring):
            raise TypeError(
                'objects_iter cannot be `str` or `bytes` instance. It must be '
                'a list, tuple or iterator of object names'
            )

        # turn list like objects into an iterator.
        objects_iter = itertools.chain(objects_iter)

        obj_batch = []
        exit_loop = False
        while not exit_loop:
            try:
                object_name = next(objects_iter)
                is_non_empty_string(object_name)
            except StopIteration:
                exit_loop = True

            if not exit_loop:
                obj_batch.append(object_name)

            # if we have 1000 items in the batch, or we have to exit
            # the loop, we have to make a request to delete objects.
            if len(obj_batch) == 1000 or (exit_loop and len(obj_batch) > 0):
                # send request and parse response
                errs_result = self._process_remove_objects_batch(
                    bucket_name, obj_batch
                )

                # return the delete errors.
                for err_result in errs_result:
                    yield err_result

                # clear batch for next set of items
                obj_batch = []

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

    def _list_incomplete_uploads(self, bucket_name, prefix=None,
                                 recursive=False, is_aggregate_size=True):
        """
        List incomplete uploads list all previously uploaded incomplete multipart objects.

        :param bucket_name: Bucket name to list uploaded objects.
        :param prefix: String specifying objects returned must begin with.
        :param recursive: If yes, returns all incomplete objects for a specified prefix.
        :return: An generator of incomplete uploads in alphabetical order.
        """
        is_valid_bucket_name(bucket_name)

        # Initialize query parameters.
        query = {
            'uploads': '',
            'max-uploads': '1000'
        }

        if prefix:
            query['prefix'] = prefix
        if not recursive:
            query['delimiter'] = '/'

        key_marker, upload_id_marker = None, None
        is_truncated = True
        while is_truncated:
            if key_marker:
                query['key-marker'] = key_marker
            if upload_id_marker:
                query['upload-id-marker'] = upload_id_marker

            response = self._url_open('GET',
                                      bucket_name=bucket_name,
                                      query=query)
            (uploads, is_truncated, key_marker,
             upload_id_marker) = parse_list_multipart_uploads(response.data,
                                                              bucket_name=bucket_name)
            for upload in uploads:
                if is_aggregate_size:
                    upload.size = self._get_total_multipart_upload_size(
                        upload.bucket_name,
                        upload.object_name,
                        upload.upload_id)
                yield upload

    def _get_total_multipart_upload_size(self, bucket_name, object_name,
                                         upload_id):
        """
        Get total multipart upload size.

        :param bucket_name: Bucket name to list parts for.
        :param object_name: Object name to list parts for.
        :param upload_id: Upload id of the previously uploaded object name.
        """
        return sum(
            [part.size for part in
             self._list_object_parts(bucket_name, object_name, upload_id)]
        )

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

        query = {
            'uploadId': upload_id,
            'max-parts': '1000'
        }

        is_truncated = True
        part_number_marker = None
        while is_truncated:
            if part_number_marker:
                query['part-number-marker'] = str(part_number_marker)

            response = self._url_open('GET',
                                      bucket_name=bucket_name,
                                      object_name=object_name,
                                      query=query)

            parts, is_truncated, part_number_marker = parse_list_parts(
                response.data,
                bucket_name=bucket_name,
                object_name=object_name,
                upload_id=upload_id
            )
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
                             expires=timedelta(days=7),
                             response_headers=None):
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
                                                  expires,
                                                  response_headers=response_headers)

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

        presign_url = presign_v4('PUT', url,
                                 self._access_key,
                                 self._secret_key,
                                 region=region,
                                 expires=int(expires.total_seconds()))
        return presign_url

    def presigned_post_policy(self, post_policy):
        """
        Provides a POST form data that can be used for object uploads.

        Example:
            post_policy = PostPolicy()
            post_policy.set_bucket_name('bucket_name')
            post_policy.set_key_startswith('objectPrefix/')

            expires_date = datetime.utcnow()+timedelta(days=10)
            post_policy.set_expires(expires_date)

            print(presigned_post_policy(post_policy))

        :param post_policy: Post_Policy object.
        :return: PostPolicy form dictionary to be used in curl or HTML forms.
        """
        post_policy.is_valid()

        date = datetime.utcnow()
        iso8601_date = date.strftime("%Y%m%dT%H%M%SZ")
        region = self._get_bucket_region(post_policy.form_data['bucket'])
        credential_string = generate_credential_string(self._access_key,
                                                       date, region)

        post_policy.policies.append(('eq', '$x-amz-date', iso8601_date))
        post_policy.policies.append(
            ('eq', '$x-amz-algorithm', _SIGN_V4_ALGORITHM))
        post_policy.policies.append(
            ('eq', '$x-amz-credential', credential_string))

        post_policy_base64 = post_policy.base64()
        signature = post_presign_signature(date, region,
                                           self._secret_key,
                                           post_policy_base64)
        post_policy.form_data.update({
            'policy': post_policy_base64,
            'x-amz-algorithm': _SIGN_V4_ALGORITHM,
            'x-amz-credential': credential_string,
            'x-amz-date': iso8601_date,
            'x-amz-signature': signature,
        })
        url_str = get_target_url(self._endpoint_url,
                                 bucket_name=post_policy.form_data['bucket'],
                                 bucket_region=region)
        return (url_str, post_policy.form_data)

    # All private functions below.
    def _get_partial_object(self, bucket_name, object_name,
                            offset=0, length=0, request_headers=None):
        """Retrieves an object from a bucket.

        Optionally takes an offset and length of data to retrieve.

        It returns a response object whose content is not
        pre-loaded. This means that the connection associated with the
        response needs to be released (for efficient re-use) after
        usage with `response.release_conn()`. Otherwise, the
        connection will linger until the object is garbage collected,
        when the connection is simply closed and not re-used.

        Examples:
            partial_object = minio.get_partial_object('foo', 'bar', 2, 4)

        :param bucket_name: Bucket to retrieve object from
        :param object_name: Name of object to retrieve
        :param offset: Optional offset to retrieve bytes from.
           Must be >= 0.
        :param length: Optional number of bytes to retrieve.
           Must be > 0.
        :param request_headers: Any additional metadata to be uploaded along
            with request.
        :return: :class:`urllib3.response.HTTPResponse` object.

        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        headers = {}
        if request_headers:
            headers = request_headers

        if offset != 0 or length != 0:
            request_range = '{}-{}'.format(
                offset, "" if length == 0 else offset + length - 1
            )
            headers['Range'] = 'bytes=' + request_range

        response = self._url_open('GET',
                                  bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers,
                                  preload_content=False)

        return response

    def _presigned_get_partial_object(self, bucket_name, object_name,
                                      expires=timedelta(days=7),
                                      offset=0, length=0,
                                      response_headers=None):
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

        region = self._get_bucket_region(bucket_name)
        url = get_target_url(self._endpoint_url,
                             bucket_name=bucket_name,
                             object_name=object_name,
                             bucket_region=region)

        headers = {}
        if offset != 0 or length != 0:
            request_range = '{}-{}'.format(
                offset, "" if length == 0 else offset + length - 1
            )
            headers['Range'] = 'bytes=' + request_range

        presign_url = presign_v4('GET', url,
                                 self._access_key,
                                 self._secret_key,
                                 region=region,
                                 headers=headers,
                                 response_headers=response_headers,
                                 expires=int(expires.total_seconds()))
        return presign_url

    def _do_put_multipart_object(self, bucket_name, object_name, part_metadata,
                                 upload_id='', part_number=0):
        """
        Initiate a multipart PUT operation for a part number.

        :param bucket_name: Bucket name for the multipart request.
        :param object_name: Object name for the multipart request.
        :param part_metadata: Part-data and metadata for the multipart request.
        :param upload_id: Upload id of the multipart request.
        :param part_number: Part number of the data to be uploaded.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)
        data = part_metadata.data
        if not callable(getattr(data, 'read')):
            raise ValueError(
                'Invalid input data does not implement a callable read() method')

        # Convert hex representation of md5 content to base64
        md5content_b64 = codecs.encode(codecs.decode(
            part_metadata.md5_hex, 'hex_codec'), 'base64_codec').strip()

        headers = {
            'Content-Length': part_metadata.size,
            'Content-Md5': md5content_b64.decode()
        }

        response = self._url_open(
            'PUT', bucket_name=bucket_name,
            object_name=object_name,
            query={'uploadId': upload_id,
                   'partNumber': str(part_number)},
            headers=headers,
            body=data,
            content_sha256=part_metadata.sha256_hex
        )

        return response.headers['etag'].replace('"', '')

    def _do_put_object(self, bucket_name, object_name, data,
                       metadata=None):
        """
        Initiate a single PUT operation.

        :param bucket_name: Bucket name for the put request.
        :param object_name: Object name for the put request.
        :param data: Input data for the put request.
        :param metadata: Any additional metadata to be uploaded along
           with your object.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        # Accept only bytes - otherwise we need to know how to encode
        # the data to bytes before storing in the object.
        if not isinstance(data, bytes):
            raise ValueError('Input data must be bytes type')

        headers = {}
        if metadata:
            headers = metadata

        headers['Content-Length'] = len(data)
        headers['Content-Md5'] = get_md5_base64digest(data)

        response = self._url_open('PUT', bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers,
                                  body=io.BytesIO(data),
                                  content_sha256=get_sha256_hexdigest(data))

        etag = response.headers.get('etag', '').replace('"', '')

        # Returns etag here.
        return etag

    def _stream_put_object(self, bucket_name, object_name,
                           data, content_size,
                           metadata=None):
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
            raise ValueError(
                'Invalid input data does not implement a callable read() method')

        # get upload id.
        upload_id = self._get_upload_id(bucket_name, object_name, metadata)

        # Initialize variables
        total_uploaded = 0

        # Calculate optimal part info.
        total_parts_count, part_size, last_part_size = optimal_part_info(
            content_size)

        # Iter over the uploaded parts.
        parts_iter = self._list_object_parts(bucket_name,
                                             object_name,
                                             upload_id)

        # save uploaded parts for verification.
        uploaded_parts = {part.part_number: part for part in parts_iter}

        # Generate new parts and upload <= current_part_size until
        # part_number reaches total_parts_count calculated for the
        # given size. Additionally part_manager() also provides
        # md5digest and sha256digest for the partitioned data.
        for part_number in range(1, total_parts_count + 1):
            current_part_size = (part_size if part_number < total_parts_count
                                 else last_part_size)

            part_metadata = parts_manager(data, current_part_size)
            md5_hex = part_metadata.md5hasher.hexdigest()

            # Verify if part number has been already uploaded.
            # Further verify if we have matching md5sum as well.
            previous_part = uploaded_parts.get(part_number, None)
            if (previous_part and previous_part.size == current_part_size and
                previous_part.etag == md5_hex):
                total_uploaded += previous_part.size
                continue

            # Seek back to starting position.
            part_metadata.data.seek(0)
            etag = self._do_put_multipart_object(bucket_name,
                                                 object_name,
                                                 part_metadata,
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
        mpart_result = self._complete_multipart_upload(bucket_name,
                                                       object_name,
                                                       upload_id,
                                                       uploaded_parts)
        # Return etag here.
        return mpart_result.etag

    def _remove_incomplete_upload(self, bucket_name, object_name, upload_id):
        """
        Remove incomplete multipart request.

        :param bucket_name: Bucket name of the incomplete upload.
        :param object_name: Object name of incomplete upload.
        :param upload_id: Upload id of the incomplete upload.
        """

        # No reason to store successful response, for errors
        # relevant exceptions are thrown.
        self._url_open('DELETE', bucket_name=bucket_name,
                       object_name=object_name, query={'uploadId': upload_id},
                       headers={})

    def _new_multipart_upload(self, bucket_name, object_name,
                              metadata=None):
        """
        Initialize new multipart upload request.

        :param bucket_name: Bucket name of the new multipart request.
        :param object_name: Object name of the new multipart request.
        :param metadata: Additional new metadata for the new object.
        :return: Returns an upload id.
        """
        is_valid_bucket_name(bucket_name)
        is_non_empty_string(object_name)

        response = self._url_open('POST', bucket_name=bucket_name,
                                  object_name=object_name,
                                  query={'uploads': ''},
                                  headers=metadata)

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

        data = xml_marshal_complete_multipart_upload(uploaded_parts)
        sha256_hex = get_sha256_hexdigest(data)
        md5_base64 = get_md5_base64digest(data)

        headers = {
            'Content-Length': len(data),
            'Content-Type': 'application/xml',
            'Content-Md5': md5_base64,
        }

        response = self._url_open('POST', bucket_name=bucket_name,
                                  object_name=object_name,
                                  query={'uploadId': upload_id},
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

        # Region set in constructor, return right here.
        if self._region:
            return self._region

        # get bucket location for Amazon S3.
        region = 'us-east-1'  # default to US standard.
        if bucket_name in self._region_map:
            region = self._region_map[bucket_name]
        else:
            region = self._get_bucket_location(bucket_name)
            self._region_map[bucket_name] = region

        # Success.
        return region

    def _get_bucket_location(self, bucket_name):
        """
        Get bucket location.

        :param bucket_name: Fetches location of the Bucket name.
        :return: location of bucket name is returned.
        """
        method = 'GET'
        url = self._endpoint_url + '/' + bucket_name + '?location='
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
                                      headers=headers)

        if self._trace_output_stream:
            dump_http(method, url, headers, response,
                      self._trace_output_stream)

        if response.status != 200:
            raise ResponseError(response, method, bucket_name).get_exception()

        location = parse_location_constraint(response.data)
        # location is empty for 'US standard region'
        if not location:
            return 'us-east-1'
        # location can be 'EU' convert it to meaningful 'eu-west-1'
        if location == 'EU':
            return 'eu-west-1'
        return location

    def _url_open(self, method, bucket_name=None, object_name=None,
                  query=None, body=None, headers={}, content_sha256=None,
                  preload_content=True):
        """
        Open a url wrapper around signature version '4'
           and :meth:`urllib3.PoolManager.urlopen`
        """
        # HTTP headers are case insensitive filter out
        # all duplicate headers and pick one.
        fold_case_headers = FoldCaseDict()

        # Set user agent once before executing the request.
        fold_case_headers['User-Agent'] = self._user_agent
        for header in headers:
            fold_case_headers[header] = headers[header]

        # Get bucket region.
        region = self._get_bucket_region(bucket_name)

        # Construct target url.
        url = get_target_url(self._endpoint_url, bucket_name=bucket_name,
                             object_name=object_name, bucket_region=region,
                             query=query)

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          fold_case_headers, self._access_key,
                          self._secret_key, content_sha256)

        response = self._http.urlopen(method, url,
                                      body=body,
                                      headers=headers,
                                      preload_content=preload_content)

        if self._trace_output_stream:
            dump_http(method, url, fold_case_headers, response,
                      self._trace_output_stream)

        if response.status != 200 and response.status != 204 \
           and response.status != 206:
            # Upon any response error invalidate the region cache
            # proactively for the bucket name.
            self._delete_bucket_region(bucket_name)

            # In case we did not preload_content, we need to release
            # the connection:
            if not preload_content:
                response.release_conn()

            supported_methods = [
                'HEAD',
                'GET',
                'POST',
                'PUT',
                'DELETE'
            ]

            if method in supported_methods:
                raise ResponseError(response,
                                    method,
                                    bucket_name,
                                    object_name).get_exception()
            else:
                raise ValueError('Unsupported method returned'
                                 ' error: {0}'.format(response.status))

        return response
