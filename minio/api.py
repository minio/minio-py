# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017 MinIO, Inc.
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

# pylint: disable=too-many-lines

"""
minio.api
~~~~~~~~~~~~

This module implements the API.

:copyright: (c) 2015, 2016, 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import

import io
import itertools
import json
import os
import platform
from datetime import datetime, timedelta
from threading import Thread

import certifi
import dateutil.parser
import urllib3

from . import __title__, __version__
from .compat import range  # pylint: disable=redefined-builtin
from .compat import basestring, quote, urlencode, urlsplit
from .credentials import Chain, Credentials, EnvAWS, EnvMinio, Static
from .definitions import Object, UploadPart
from .error import (AccessDenied, InvalidArgumentError, InvalidSizeError,
                    InvalidXMLError, NoSuchBucket, ResponseError)
from .fold_case_dict import FoldCaseDict
from .helpers import (DEFAULT_PART_SIZE, MAX_MULTIPART_COUNT, MAX_PART_SIZE,
                      MAX_POOL_SIZE, MIN_PART_SIZE, amzprefix_user_metadata,
                      dump_http, get_md5_base64digest,
                      get_s3_region_from_endpoint, get_scheme_host,
                      get_sha256_hexdigest, get_target_url, is_amz_header,
                      is_non_empty_string, is_supported_header,
                      is_valid_bucket_name, is_valid_endpoint,
                      is_valid_notification_config, is_valid_policy_type,
                      is_valid_sse_c_object, is_valid_sse_object, mkdir_p,
                      optimal_part_info, read_full)
from .parsers import (parse_assume_role, parse_copy_object,
                      parse_get_bucket_notification, parse_list_buckets,
                      parse_list_multipart_uploads, parse_list_object_versions,
                      parse_list_objects, parse_list_objects_v2,
                      parse_list_parts, parse_location_constraint,
                      parse_multi_delete_response,
                      parse_multipart_upload_result,
                      parse_new_multipart_upload)
from .select import SelectObjectReader
from .signer import (_SIGN_V4_ALGORITHM, _UNSIGNED_PAYLOAD,
                     generate_credential_string, post_presign_signature,
                     presign_v4, sign_v4)
from .sse import SseCustomerKey
from .thread_pool import ThreadPool
from .xml_marshal import (marshal_bucket_notifications,
                          marshal_complete_multipart,
                          xml_marshal_bucket_constraint,
                          xml_marshal_bucket_encryption,
                          xml_marshal_delete_objects, xml_marshal_select,
                          xml_to_dict)

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


_DEFAULT_USER_AGENT = "MinIO ({os}; {arch}) {lib}/{ver}".format(
    os=platform.system(), arch=platform.machine(),
    lib=__title__, ver=__version__,
)


# Duration of 7 days in seconds
_MAX_EXPIRY_TIME = 604800  # 7 days in seconds

# Number of parallel workers which upload parts
_PARALLEL_UPLOADERS = 3


class Minio:  # pylint: disable=too-many-public-methods
    """
    Simple Storage Service (aka S3) client to perform bucket and object
    operations.

    :param endpoint: Hostname of a S3 service.
    :param access_key: Access key (aka user ID) of your account in S3 service.
    :param secret_key: Secret Key (aka password) of your account in S3 service.
    :param session_token: Session token of your account in S3 service.
    :param secure: Flag to indicate to use secure (TLS) connection to S3
        service or not.
    :param region: Region name of buckets in S3 service.
    :param http_client: Customized HTTP client.
    :param credentials: Credentials of your account in S3 service.
    :return: :class:`Minio <Minio>` object

    Example::
        client = Minio('play.min.io')
        client = Minio('s3.amazonaws.com', 'ACCESS_KEY', 'SECRET_KEY')
        client = Minio('play.min.io', 'ACCESS_KEY', 'SECRET_KEY',
                       region='us-east-1')

    **NOTE on concurrent usage:** The `Minio` object is thread safe when using
    the Python `threading` library. Specifically, it is **NOT** safe to share
    it between multiple processes, for example when using
    `multiprocessing.Pool`. The solution is simply to create a new `Minio`
    object in each process, and not share it between processes.

    """

    # pylint: disable=too-many-function-args
    def __init__(self, endpoint, access_key=None,
                 secret_key=None,
                 session_token=None,
                 secure=True,
                 region=None,
                 http_client=None,
                 credentials=None):

        # Validate endpoint.
        is_valid_endpoint(endpoint)

        # Validate http client has correct base class.
        if http_client and not isinstance(
                http_client,
                urllib3.poolmanager.PoolManager):
            raise InvalidArgumentError(
                'HTTP client should be of instance'
                ' `urllib3.poolmanager.PoolManager`'
            )

        # Default is a secured connection.
        scheme = 'https://' if secure else 'http://'
        self._region = region or get_s3_region_from_endpoint(endpoint)
        self._region_map = dict()
        self._endpoint_url = urlsplit(scheme + endpoint).geturl()
        self._is_ssl = secure
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token
        self._user_agent = _DEFAULT_USER_AGENT
        self._trace_output_stream = None
        self._enable_s3_accelerate = False
        self._accelerate_endpoint_url = scheme + 's3-accelerate.amazonaws.com'
        self._credentials = credentials or Credentials(
            provider=Chain(
                providers=[
                    Static(access_key, secret_key, session_token),
                    EnvAWS(),
                    EnvMinio(),
                ]
            )
        )

        # Load CA certificates from SSL_CERT_FILE file if set
        ca_certs = os.environ.get('SSL_CERT_FILE') or certifi.where()
        self._http = http_client or urllib3.PoolManager(
            timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
            maxsize=MAX_POOL_SIZE,
            cert_reqs='CERT_REQUIRED',
            ca_certs=ca_certs,
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def set_app_info(self, app_name, app_version):
        """
        Set your application name and version to user agent header.

        :param app_name: Application name.
        :param app_version: Application version.

        Example::
            client.set_app_info('my_app', '1.0.2')
        """
        if not (app_name and app_version):
            raise ValueError("Application name/version cannot be empty.")

        self._user_agent = "{0} {1}/{2}".format(
            _DEFAULT_USER_AGENT, app_name, app_version,
        )

    def trace_on(self, stream):
        """
        Enable http trace.

        :param output_stream: Stream for writing HTTP call tracing.
        """
        if not stream:
            raise ValueError('Input stream for trace output is invalid.')
        # Save new output stream.
        self._trace_output_stream = stream

    def trace_off(self):
        """
        Disable HTTP trace.
        """
        self._trace_output_stream = None

    def use_s3_accelerate(self, value):
        """Enable AWS S3 accelerated endpoint."""

        _, host = get_scheme_host(urlsplit(self._endpoint_url))
        if 's3.amazonaws.com' in host:
            self._enable_s3_accelerate = value is True

    def select_object_content(self, bucket_name, object_name, opts):
        """
        Select content of an object by SQL expression.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param opts: Options for select object.
        :return: A reader contains requested records and progress information.

        Example::
            data = client.select_object_content('foo', 'test.csv', options)
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        content = xml_marshal_select(opts)
        url_values = {
            "select": "",
            "select-type": "2",
        }
        headers = {
            'Content-Length': str(len(content)),
            'Content-Md5': get_md5_base64digest(content)
        }
        content_sha256_hex = get_sha256_hexdigest(content)
        response = self._url_open(
            'POST',
            bucket_name=bucket_name,
            object_name=object_name,
            query=url_values,
            headers=headers,
            body=content,
            content_sha256=content_sha256_hex,
            preload_content=False)

        return SelectObjectReader(response)

    def make_bucket(self, bucket_name, location='us-east-1',
                    object_lock=False):
        """
        Create a bucket with region and object lock.

        :param bucket_name: Name of the bucket.
        :param location: Region in which the bucket will be created.
        :param object_lock: Flag to set object-lock feature.

        Examples::
            minio.make_bucket('foo')
            minio.make_bucket('foo', 'us-west-1')
            minio.make_bucket('foo', 'us-west-1', object_lock=True)
        """
        is_valid_bucket_name(bucket_name, True)

        # Default region for all requests.
        region = self._region or 'us-east-1'
        # Validate if caller requested bucket location is same as current
        # region
        if self._region and self._region != location:
            raise InvalidArgumentError(
                "Configured region {0}, requested {1}".format(
                    self._region, location))

        method = 'PUT'
        # Set user agent once before the request.
        headers = {'User-Agent': self._user_agent}
        if object_lock:
            headers["x-amz-bucket-object-lock-enabled"] = "true"

        content = None
        if location and location != 'us-east-1':
            content = xml_marshal_bucket_constraint(location)
            headers['Content-Length'] = str(len(content))
            headers['Content-Md5'] = get_md5_base64digest(content)

        content_sha256_hex = get_sha256_hexdigest(content)

        # In case of Amazon S3.  The make bucket issued on already
        # existing bucket would fail with 'AuthorizationMalformed'
        # error if virtual style is used. So we default to 'path
        # style' as that is the preferred method here. The final
        # location of the 'bucket' is provided through XML
        # LocationConstraint data with the request.
        # Construct target url.
        url = self._endpoint_url + '/' + bucket_name + '/'

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers,
                          self._credentials,
                          content_sha256_hex,
                          datetime.utcnow())

        if self._trace_output_stream:
            dump_http(method, url, headers, None,
                      self._trace_output_stream)

        response = self._http.urlopen(method, url,
                                      body=content,
                                      headers=headers)

        if self._trace_output_stream:
            dump_http(method, url, headers, response,
                      self._trace_output_stream)

        if response.status != 200:
            raise ResponseError(response, method, bucket_name).get_exception()

        self._set_bucket_region(bucket_name, region=location)

    def list_buckets(self):
        """
        List information of all accessible buckets.

        :return: An iterator contains bucket information.

        Example::
            bucket_list = minio.list_buckets()
            for bucket in bucket_list:
                print(bucket.name, bucket.created_date)
        """

        method = 'GET'
        url = get_target_url(self._endpoint_url)
        # Set user agent once before the request.
        headers = {'User-Agent': self._user_agent}

        # default for all requests.
        region = self._region or 'us-east-1'

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          headers,
                          self._credentials,
                          None, datetime.utcnow())

        if self._trace_output_stream:
            dump_http(method, url, headers, None,
                      self._trace_output_stream)

        response = self._http.urlopen(method, url,
                                      body=None,
                                      headers=headers)

        if self._trace_output_stream:
            dump_http(method, url, headers, response,
                      self._trace_output_stream)

        if response.status != 200:
            raise ResponseError(response, method).get_exception()
        try:
            return parse_list_buckets(response.data)
        except InvalidXMLError:
            if self._endpoint_url.endswith("s3.amazonaws.com") and (
                    not self._access_key or not self._secret_key):
                raise AccessDenied(response)

    def bucket_exists(self, bucket_name):
        """
        Check if a bucket exists.

        :param bucket_name: Name of the bucket.
        :return: True if the bucket exists.

        Example::
            found = minio.bucket_exists("my-bucketname")
            if found:
                print("my-bucketname exists")
            else:
                print("my-bucketname does not exist")
        """
        is_valid_bucket_name(bucket_name, False)

        try:
            self._url_open('HEAD', bucket_name=bucket_name)
            return True
        except NoSuchBucket:
            # If bucket has not been created yet, MinIO returns NoSuchBucket
            # error.
            return False

    def remove_bucket(self, bucket_name):
        """
        Remove an empty bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.remove_bucket("my-bucketname")
        """
        is_valid_bucket_name(bucket_name, False)
        self._url_open('DELETE', bucket_name=bucket_name)

        # Make sure to purge bucket_name from region cache.
        self._delete_bucket_region(bucket_name)

    def get_bucket_policy(self, bucket_name):
        """
        Get bucket policy configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: Bucket policy configuration as JSON string.

        Example::
            config = minio.get_bucket_policy("my-bucketname")
        """
        is_valid_bucket_name(bucket_name, False)

        response = self._url_open("GET",
                                  bucket_name=bucket_name,
                                  query={"policy": ""})
        return response.data

    def delete_bucket_policy(self, bucket_name):
        """
        Delete bucket policy configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_policy("my-bucketname")
        """
        self._url_open("DELETE",
                       bucket_name=bucket_name,
                       query={"policy": ""})

    def set_bucket_policy(self, bucket_name, policy):
        """
        Set bucket policy configuration to a bucket.

        :param bucket_name: Name of the bucket.
        :param policy: Bucket policy configuration as JSON string.

        Example::
            minio.get_bucket_policy("my-bucketname", config)
        """
        is_valid_policy_type(policy)

        is_valid_bucket_name(bucket_name, False)

        headers = {
            'Content-Length': str(len(policy)),
            'Content-Md5': get_md5_base64digest(policy)
        }
        content_sha256_hex = get_sha256_hexdigest(policy)
        self._url_open("PUT",
                       bucket_name=bucket_name,
                       query={"policy": ""},
                       headers=headers,
                       body=policy,
                       content_sha256=content_sha256_hex)

    def get_bucket_notification(self, bucket_name):
        """
        Get notification configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: Notification configuration.

        Example::
            config = minio.get_bucket_notification("my-bucketname")
        """
        is_valid_bucket_name(bucket_name, False)

        response = self._url_open(
            "GET",
            bucket_name=bucket_name,
            query={"notification": ""},
        )
        data = response.data.decode('utf-8')
        return parse_get_bucket_notification(data)

    def set_bucket_notification(self, bucket_name, notifications):
        """
        Set notification configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :param notifications: Notification configuration to be set.

        Example::
            minio.set_bucket_notification("my-bucketname", config)
        """
        is_valid_bucket_name(bucket_name, False)
        is_valid_notification_config(notifications)

        content = marshal_bucket_notifications(notifications)
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
        Remove notification configuration of a bucket. On success, S3 service
        stops notification of events previously set of the bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.remove_all_bucket_notification("my-bucketname")
        """
        is_valid_bucket_name(bucket_name, False)

        content_bytes = marshal_bucket_notifications({})
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

    def put_bucket_encryption(self, bucket_name, enc_config):
        """
        Set encryption configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :param enc_config: Encryption configuration as dictionary to be set.

        Example::
            minio.put_bucket_encryption("my-bucketname", config)
        """
        is_valid_bucket_name(bucket_name, False)

        # 'Rule' is a list, so we need to go through each one of
        # its key/value pair and collect the encryption values.
        rules = enc_config['ServerSideEncryptionConfiguration']['Rule']
        enc_config_xml = xml_marshal_bucket_encryption(rules)

        headers = {
            'Content-Length': str(len(enc_config_xml)),
            'Content-Md5': get_md5_base64digest(enc_config_xml)
        }
        content_sha256_hex = get_sha256_hexdigest(enc_config_xml)
        self._url_open("PUT",
                       bucket_name=bucket_name,
                       query={"encryption": ""},
                       headers=headers,
                       body=enc_config_xml,
                       content_sha256=content_sha256_hex
                       )

    def get_bucket_encryption(self, bucket_name):
        """
        Get encryption configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: Encryption configuration.

        Example::
            config = minio.get_bucket_encryption("my-bucketname")
        """
        is_valid_bucket_name(bucket_name, False)

        response = self._url_open(
            "GET",
            bucket_name=bucket_name,
            query={"encryption": ""}
        )
        return xml_to_dict(response.data.decode('utf-8'))

    def delete_bucket_encryption(self, bucket_name):
        """
        Delete encryption configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_encryption("my-bucketname")
        """
        is_valid_bucket_name(bucket_name, False)

        self._url_open(
            'DELETE',
            bucket_name=bucket_name,
            query={"encryption": ""}
        )

    def listen_bucket_notification(self, bucket_name, prefix='', suffix='',
                                   events=('s3:ObjectCreated:*',
                                           's3:ObjectRemoved:*',
                                           's3:ObjectAccessed:*')):
        """
        Listen events of object prefix and suffix of a bucket. Caller should
        iterate returned iterator to read new events.

        :param bucket_name: Name of the bucket.
        :param prefix: Listen events of object starts with prefix.
        :param suffix: Listen events of object ends with suffix.
        :param events: Events to listen.
        :return: Iterator contains event records.

        Example::
            iter = minio.listen_bucket_notification(
                "my-bucketname",
                events=('s3:ObjectCreated:*', 's3:ObjectAccessed:*'),
            )
            for events in iter:
                print(events)
        """
        is_valid_bucket_name(bucket_name, False)

        # If someone explicitly set prefix to None convert it to empty string.
        prefix = prefix or ''

        # If someone explicitly set suffix to None convert it to empty string.
        suffix = suffix or ''

        url_components = urlsplit(self._endpoint_url)
        if url_components.hostname == 's3.amazonaws.com':
            raise InvalidArgumentError(
                'Listening for event notifications on a bucket is a MinIO '
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
                    if line.strip():
                        if hasattr(line, 'decode'):
                            line = line.decode('utf-8')
                        event = json.loads(line)
                        if event['Records']:
                            yield event
            except JSONDecodeError:
                response.close()
                continue

    def _do_bucket_versioning(self, bucket_name, status):
        """Do versioning support in a bucket."""
        is_valid_bucket_name(bucket_name, False)
        config = (
            '<VersioningConfiguration '
            'xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            '<Status>{0}</Status></VersioningConfiguration>'
        ).format("Enabled" if status else "Suspended")
        body = config.encode()
        headers = {
            'Content-Length': str(len(body)),
            'Content-Md5': get_md5_base64digest(body)
        }
        content_sha256_hex = get_sha256_hexdigest(body)
        self._url_open(
            "PUT",
            bucket_name=bucket_name,
            query={"versioning": ""},
            headers=headers,
            body=body,
            content_sha256=content_sha256_hex,
        )

    def enable_bucket_versioning(self, bucket_name):
        """
        Enable object versioning feature in a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.enable_bucket_versioning("my-bucketname")
        """
        self._do_bucket_versioning(bucket_name, True)

    def disable_bucket_versioning(self, bucket_name):
        """
        Disable object versioning feature in a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.disable_bucket_versioning("my-bucketname")
        """
        self._do_bucket_versioning(bucket_name, False)

    def fput_object(self, bucket_name, object_name, file_path,
                    content_type='application/octet-stream',
                    metadata=None, sse=None, progress=None,
                    part_size=DEFAULT_PART_SIZE):
        """
        Uploads data from a file to an object in a bucket.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param file_path: Name of file to upload.
        :param content_type: Content type of the object.
        :param metadata: Any additional metadata to be uploaded along
            with your PUT request.
        :param sse: Server-side encryption.
        :param progress: A progress object
        :param part_size: Multipart part size
        :return: etag and version ID if available.

        Example::
            minio.fput_object('foo', 'bar', 'filepath', 'text/plain')
        """

        # Open file in 'read' mode.
        with open(file_path, 'rb') as file_data:
            file_size = os.stat(file_path).st_size
            return self.put_object(bucket_name, object_name, file_data,
                                   file_size, content_type, metadata, sse,
                                   progress, part_size)

    def fget_object(self, bucket_name, object_name, file_path,
                    request_headers=None, sse=None, version_id=None,
                    extra_query_params=None):
        """
        Downloads data of an object to file.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param file_path: Name of file to upload.
        :param request_headers: Any additional headers to be added with GET
                                request.
        :param sse: Server-side encryption customer key.
        :param version_id: Version-ID of the object.
        :param extra_query_params: Extra query parameters for advanced usage.
        :return: Object information.

        Example::
            minio.fget_object('foo', 'bar', 'localfile')
            minio.fget_object(
                'foo', 'bar', 'localfile', version_id='VERSION-ID',
            )
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        if os.path.isdir(file_path):
            raise OSError("file is a directory.")

        # Create top level directory if needed.
        top_level_dir = os.path.dirname(file_path)
        if top_level_dir:
            mkdir_p(top_level_dir)

        stat = self.stat_object(
            bucket_name,
            object_name,
            sse,
            version_id=version_id,
        )

        # Write to a temporary file "file_path.part.minio" before saving.
        file_part_path = file_path + stat.etag + '.part.minio'

        # Open file in 'overwrite' mode.
        with open(file_part_path, 'wb') as file_part_data:
            # Save current file_part statinfo.
            file_statinfo = os.stat(file_part_path)

            # Get partial object.
            response = self._get_partial_object(
                bucket_name,
                object_name,
                offset=file_statinfo.st_size,
                length=0,
                request_headers=request_headers,
                sse=sse,
                version_id=version_id,
                extra_query_params=extra_query_params,
            )

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
                msg = ('Data written {0} bytes is smaller than the specified'
                       ' size {1} bytes').format(total_written, content_size)
                raise InvalidSizeError(msg)

            if total_written > content_size:
                msg = ('Data written {0} bytes is in excess than the specified'
                       ' size {1} bytes').format(total_written, content_size)
                raise InvalidSizeError(msg)

        # Delete existing file to be compatible with Windows
        if os.path.exists(file_path):
            os.remove(file_path)
        # Rename with destination file path
        os.rename(file_part_path, file_path)

        # Return the stat
        return stat

    def get_object(self, bucket_name, object_name, request_headers=None,
                   sse=None, version_id=None, extra_query_params=None):
        """
        Get data of an object. Returned response should be closed after use to
        release network resources. To reuse the connection, its required to
        call `response.release_conn()` explicitly.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param request_headers: Any additional headers to be added with GET
                                request.
        :param sse: Server-side encryption customer key.
        :param version_id: Version-ID of the object.
        :param extra_query_params: Extra query parameters for advanced usage.
        :return: :class:`urllib3.response.HTTPResponse` object.

        Example::
            try:
                response = minio.get_object('foo', 'bar')
                // Read data from response.
            finally:
                response.close()
                response.release_conn()
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        return self._get_partial_object(
            bucket_name,
            object_name,
            request_headers=request_headers,
            sse=sse,
            version_id=version_id,
            extra_query_params=extra_query_params,
        )

    def get_partial_object(self, bucket_name, object_name, offset=0, length=0,
                           request_headers=None, sse=None, version_id=None,
                           extra_query_params=None):
        """
        Gets data from offset to length of an object. Returned response should
        be closed after use to release network resources. To reuse the
        connection, its required to call `response.release_conn()` explicitly.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param offset: Start byte position of object data.
        :param length: Number of bytes of object data from offset.
        :param request_headers: Any additional headers to be added with GET
                                request.
        :param sse: Server-side encryption customer key.
        :param version_id: Version-ID of the object.
        :param extra_query_params: Extra query parameters for advanced usage.
        :return: :class:`urllib3.response.HTTPResponse` object.

        Example::
            try:
                response = minio.get_partial_object('foo', 'bar', 2, 4)
                // Read data from response.
            finally:
                response.close()
                response.release_conn()
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        return self._get_partial_object(
            bucket_name,
            object_name,
            offset,
            length,
            request_headers=request_headers,
            sse=sse,
            version_id=version_id,
            extra_query_params=extra_query_params,
        )

    def copy_object(self, bucket_name, object_name, object_source,
                    conditions=None, source_sse=None, sse=None, metadata=None):
        """
        Create an object by server-side copying data from another object.
        In this API maximum supported source object size is 5GiB.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param object_source: Source object to be copied.
        :param conditions: :class:`CopyConditions` object. Collection of
                           supported CopyObject conditions.
        :param source_sse: Server-side encryption customer key of source
                           object.
        :param sse: Server-side encryption of destination object.
        :param metadata: Any user-defined metadata to be copied along with
                         destination object.
        :return: :class:`CopyObjectResult`

        Example::
            minio.copy_object(
                "my-bucketname",
                "my-objectname",
                "my-source-bucketname/my-source-bucketname",
            )
            minio.copy_object(
                "my-bucketname",
                "my-objectname",
                "my-source-bucketname/my-source-bucketname"
                "?versionId=b6602757-7c9c-449b-937f-fed504d04c94",
            )
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)
        is_non_empty_string(object_source)

        headers = {}

        # Preserving the user-defined metadata in headers
        if metadata:
            headers = amzprefix_user_metadata(metadata)
            headers["x-amz-metadata-directive"] = "REPLACE"

        if conditions:
            headers.update(conditions)

        # Source argument to copy_object can only be of type SSE-C
        if source_sse:
            is_valid_sse_c_object(source_sse)
            headers.update(source_sse.copy_headers())

        # Destination argument to copy_object cannot be of type SSE-C
        if sse:
            is_valid_sse_object(sse)
            headers.update(sse.headers())

        headers['X-Amz-Copy-Source'] = quote(object_source)

        response = self._url_open('PUT',
                                  bucket_name=bucket_name,
                                  object_name=object_name,
                                  headers=headers)

        return parse_copy_object(bucket_name, object_name, response.data)

    def put_object(self, bucket_name, object_name, data, length,
                   content_type='application/octet-stream',
                   metadata=None, sse=None, progress=None,
                   part_size=DEFAULT_PART_SIZE):
        """
        Uploads data from a stream to an object in a bucket.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param data: Contains object data.
        :param content_type: Content type of the object.
        :param metadata: Any additional metadata to be uploaded along
            with your PUT request.
        :param sse: Server-side encryption.
        :param progress: A progress object
        :param part_size: Multipart part size
        :return: etag and version ID if available.

        Example::
            file_stat = os.stat('hello.txt')
            with open('hello.txt', 'rb') as data:
                minio.put_object(
                    'foo', 'bar', data, file_stat.st_size, 'text/plain',
                )
        """
        is_valid_sse_object(sse)
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        if progress:
            if not isinstance(progress, Thread):
                raise TypeError('Progress object should inherit the thread.')
            # Set progress bar length and object name before upload
            progress.set_meta(total_length=length, object_name=object_name)

        if not callable(getattr(data, 'read')):
            raise ValueError(
                'Invalid input data does not implement'
                ' a callable read() method')

        if length > (part_size * MAX_MULTIPART_COUNT):
            raise InvalidArgumentError('Part size * max_parts(10000) is '
                                       ' lesser than input length.')

        if part_size < MIN_PART_SIZE:
            raise InvalidArgumentError('Input part size is smaller '
                                       ' than allowed minimum of 5MiB.')

        if part_size > MAX_PART_SIZE:
            raise InvalidArgumentError('Input part size is bigger '
                                       ' than allowed maximum of 5GiB.')

        if not metadata:
            metadata = {}

        metadata = amzprefix_user_metadata(metadata)
        metadata['Content-Type'] = content_type or 'application/octet-stream'

        if length > part_size:
            return self._stream_put_object(bucket_name, object_name,
                                           data, length, metadata=metadata,
                                           sse=sse, progress=progress,
                                           part_size=part_size)

        current_data = data.read(length)
        if len(current_data) != length:
            raise InvalidArgumentError(
                'Could not read {} bytes from data to upload'.format(length)
            )

        return self._do_put_object(bucket_name, object_name,
                                   current_data, len(current_data),
                                   metadata=metadata, sse=sse,
                                   progress=progress)

    def list_objects(self, bucket_name, prefix=None, recursive=False,
                     include_version=False):
        """
        Lists object information of a bucket using S3 API version 1, optionally
        for prefix recursively.

        :param bucket_name: Name of the bucket.
        :param prefix: Object name starts with prefix.
        :param recursive: List recursively than directory structure emulation.
        :param include_version: Flag to control whether include object
                                versions.
        :return: An iterator contains object information.

        Example::
            # List objects information.
            objects = minio.list_objects('foo')
            for object in objects:
                print(object)

            # List objects information those names starts with 'hello/'.
            objects = minio.list_objects('foo', prefix='hello/')
            for object in objects:
                print(object)

            # List objects information recursively.
            objects = minio.list_objects('foo', recursive=True)
            for object in objects:
                print(object)

            # List objects information recursively those names starts with
            # 'hello/'.
            objects = minio.list_objects(
                'foo', prefix='hello/', recursive=True,
            )
            for object in objects:
                print(object)
        """
        return self._list_objects(
            bucket_name,
            delimiter=None if recursive else "/",
            prefix=prefix,
            use_version1=True,
            include_version=include_version,
        )

    def list_objects_v2(self, bucket_name, prefix=None, recursive=False,
                        start_after=None, include_user_meta=False,
                        include_version=False):
        """
        Lists object information of a bucket using S3 API version 2, optionally
        for prefix recursively.

        :param bucket_name: Name of the bucket.
        :param prefix: Object name starts with prefix.
        :param recursive: List recursively than directory structure emulation.
        :param start_after: List objects after this key name.
        :param include_user_meta: MinIO specific flag to control to include
                                 user metadata.
        :param include_version: Flag to control whether include object
                                versions.
        :return: An iterator contains object information.

        Example::
            # List objects information.
            objects = minio.list_objects_v2('foo')
            for object in objects:
                print(object)

            # List objects information those names starts with 'hello/'.
            objects = minio.list_objects_v2('foo', prefix='hello/')
            for object in objects:
                print(object)

            # List objects information recursively.
            objects = minio.list_objects_v2('foo', recursive=True)
            for object in objects:
                print(object)

            # List objects information recursively those names starts with
            # 'hello/'.
            objects = minio.list_objects_v2(
                'foo', prefix='hello/', recursive=True,
            )
            for object in objects:
                print(object)

            # List objects information recursively after object name
            # 'hello/world/1'.
            objects = minio.list_objects_v2(
                'foo', recursive=True, start_after='hello/world/1',
            )
            for object in objects:
                print(object)
        """
        return self._list_objects(
            bucket_name,
            delimiter=None if recursive else "/",
            include_user_meta=include_user_meta,
            prefix=prefix,
            start_after=start_after,
            include_version=include_version,
        )

    def stat_object(self, bucket_name, object_name, sse=None, version_id=None,
                    extra_query_params=None):
        """
        Get object information and metadata of an object.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param sse: Server-side encryption customer key.
        :param version_id: Version ID of the object.
        :param extra_query_params: Extra query parameters for advanced usage.
        :return: :class:`Object <Object>`.

        Example::
            stat = minio.stat_object("my-bucketname", "my-objectname")
        """

        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        headers = {}
        if sse:
            is_valid_sse_c_object(sse)
            headers = sse.headers()

        if version_id:
            if extra_query_params:
                extra_query_params["versionId"] = version_id
            else:
                extra_query_params = {"versionId": version_id}

        response = self._url_open(
            "HEAD",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            query=extra_query_params,
        )

        custom_metadata = {
            key: value for key, value in response.headers.items()
            if is_supported_header(key) or is_amz_header(key)
        }

        last_modified = response.headers.get("last-modified")
        if last_modified:
            last_modified = dateutil.parser.parse(last_modified).timetuple()

        return Object(
            bucket_name,
            object_name,
            last_modified=last_modified,
            etag=response.headers.get("etag", "").replace('"', ""),
            size=int(response.headers.get("content-length", "0")),
            content_type=response.headers.get("content-type"),
            metadata=custom_metadata,
            version_id=response.headers.get("x-amz-version-id"),
        )

    def remove_object(self, bucket_name, object_name, version_id=None):
        """
        Remove an object.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param version_id: Version ID of the object.

        Example::
            minio.remove_object("my-bucketname", "my-objectname")
            minio.remove_object(
                "my-bucketname",
                "my-objectname",
                version_id="13f88b18-8dcd-4c83-88f2-8631fdb6250c",
            )
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        # No reason to store successful response, for errors
        # relevant exceptions are thrown.
        self._url_open(
            "DELETE",
            bucket_name=bucket_name,
            object_name=object_name,
            query={"versionId": version_id} if version_id else None,
        )

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
        return parse_multi_delete_response(response.data)

    def remove_objects(self, bucket_name, objects_iter):
        """
        Remove multiple objects.

        :param bucket_name: Name of the bucket.
        :param objects_iter: An iterable type python object providing object
                             names for deletion.
        :return: An iterator contains
                 :class:`MultiDeleteError <MultiDeleteError>`.

        Example::
            minio.remove_objects(
                "my-bucketname",
                [
                    "my-objectname1",
                    "my-objectname2",
                    ("my-objectname3", "13f88b18-8dcd-4c83-88f2-8631fdb6250c"),
                ],
            )
        """
        is_valid_bucket_name(bucket_name, False)
        if isinstance(objects_iter, basestring):
            raise TypeError(
                'objects_iter cannot be `str` or `bytes` instance. It must be '
                'a list, tuple or iterator of object names'
            )

        # turn list like objects into an iterator.
        objects_iter = itertools.chain(objects_iter)

        def check_name(name):
            if not isinstance(name, basestring):
                name = name[0]
            is_non_empty_string(name)
            return True

        while True:
            # get 1000 entries or whatever available.
            obj_batch = [
                name for _, name in zip(range(1000), objects_iter)
                if check_name(name)
            ]

            if not obj_batch:
                break

            errs_result = self._process_remove_objects_batch(
                bucket_name, obj_batch,
            )

            # return the delete errors.
            for err_result in errs_result:
                # AWS S3 returns "NoSuchVersion" error when
                # version doesn't exist ignore this error
                # yield all errors otherwise
                if err_result.error_code != 'NoSuchVersion':
                    yield err_result

    def list_incomplete_uploads(self, bucket_name, prefix='', recursive=False):
        """
        List incomplete object upload information of a bucket, optionally for
        prefix recursively.

        :param bucket_name: Name of the bucket.
        :param prefix: Object name starts with prefix.
        :param recursive: List recursively than directory structure emulation.
        :return: An iterator contains incomplete object upload information.

        Example::
            # List incomplete object upload information.
            objects = minio.list_incomplete_uploads('foo')
            for object in objects:
                print(object)

            # List incomplete object upload information those names starts with
            # 'hello/'.
            objects = minio.list_incomplete_uploads('foo', prefix='hello/')
            for object in objects:
                print(object)

            # List incomplete object upload information recursively.
            objects = minio.list_incomplete_uploads('foo', recursive=True)
            for object in objects:
                print(object)

            # List incomplete object upload information recursively those names
            # starts with 'hello/'.
            objects = minio.list_incomplete_uploads(
                'foo', prefix='hello/', recursive=True,
            )
            for object in objects:
                print(object)
        """
        is_valid_bucket_name(bucket_name, False)

        return self._list_incomplete_uploads(bucket_name, prefix, recursive)

    def _list_incomplete_uploads(self, bucket_name, prefix='',
                                 recursive=False, is_aggregate_size=True):
        """
        List incomplete uploads list all previously uploaded incomplete
        multipart objects.

        :param bucket_name: Bucket name to list uploaded objects.
        :param prefix: String specifying objects returned must begin with.
        :param recursive: If yes, returns all incomplete objects for a
                          specified prefix.
        :return: An generator of incomplete uploads in alphabetical order.
        """
        is_valid_bucket_name(bucket_name, False)

        # If someone explicitly set prefix to None convert it to empty string.
        prefix = prefix or ''

        # Initialize query parameters.
        query = {
            'uploads': '',
            'prefix': prefix
        }

        if not recursive:
            query['delimiter'] = '/'

        key_marker, upload_id_marker = '', ''
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
                                                              bucket_name)
            for upload in uploads:
                if is_aggregate_size:
                    upload.size = self._get_all_parts_size(
                        upload.bucket_name,
                        upload.object_name,
                        upload.upload_id)
                yield upload

    def _get_all_parts_size(self, bucket_name, object_name, upload_id):
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
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)
        is_non_empty_string(upload_id)

        query = {
            'uploadId': upload_id,
        }

        is_truncated = True
        part_number_marker = ''
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
        Remove all incomplete uploads of an object.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.

        Example::
            minio.remove_incomplete_upload("my-bucketname", "my-objectname")
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        uploads = self._list_incomplete_uploads(bucket_name, object_name,
                                                recursive=True,
                                                is_aggregate_size=False)
        for upload in uploads:
            if object_name == upload.object_name:
                self._remove_incomplete_upload(bucket_name, object_name,
                                               upload.upload_id)

    def presigned_url(self, method,
                      bucket_name,
                      object_name,
                      expires=timedelta(days=7),
                      response_headers=None,
                      request_date=None,
                      version_id=None,
                      extra_query_params=None):
        """
        Get presigned URL of an object for HTTP method, expiry time and custom
        request parameters.

        :param method: HTTP method.
        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param expires: Expiry in seconds; defaults to 7 days.
        :params response_headers: Optional response_headers argument to
                                  specify response fields like date, size,
                                  type of file, data about server, etc.
        :params request_date: Optional request_date argument to
                              specify a different request date. Default is
                              current date.
        :param version_id: Version ID of the object.
        :param extra_query_params: Extra query parameters for advanced usage.
        :return: URL string.

        Example::
            # Get presigned URL string to delete 'my-objectname' in
            # 'my-bucketname' with one day expiry.
            url = minio.presigned_url(
                "DELETE",
                "my-bucketname",
                "my-objectname",
                expires=timedelta(days=1),
            )
            print(url)

            # Get presigned URL string to upload 'my-objectname' in
            # 'my-bucketname' with response-content-type as application/json
            # and one day expiry.
            url = minio.presigned_url(
                "PUT",
                "my-bucketname",
                "my-objectname",
                expires=timedelta(days=1),
                response_headers={"response-content-type": "application/json"},
            )
            print(url)

            # Get presigned URL string to download 'my-objectname' in
            # 'my-bucketname' with two hours expiry.
            url = minio.presigned_url(
                "GET",
                "my-bucketname",
                "my-objectname",
                expires=timedelta(hours=2),
            )
            print(url)
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        if (expires.total_seconds() < 1 or
                expires.total_seconds() > _MAX_EXPIRY_TIME):
            raise InvalidArgumentError(
                'Expires param valid values are between 1 sec to'
                ' {0} secs'.format(_MAX_EXPIRY_TIME))

        region = self._get_bucket_region(bucket_name)
        endpoint_url = self._endpoint_url
        if self._enable_s3_accelerate:
            endpoint_url = self._accelerate_endpoint_url

        if version_id:
            if extra_query_params:
                extra_query_params["versionId"] = version_id
            else:
                extra_query_params = {"versionId": version_id}

        url = get_target_url(
            endpoint_url,
            bucket_name=bucket_name,
            object_name=object_name,
            bucket_region=region,
            query=extra_query_params,
        )

        return presign_v4(method, url,
                          credentials=self._credentials,
                          region=region,
                          expires=int(expires.total_seconds()),
                          response_headers=response_headers,
                          request_date=request_date)

    def presigned_get_object(self, bucket_name, object_name,
                             expires=timedelta(days=7),
                             response_headers=None,
                             request_date=None,
                             version_id=None,
                             extra_query_params=None):
        """
        Get presigned URL of an object to download its data with expiry time
        and custom request parameters.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param expires: Expiry in seconds; defaults to 7 days.
        :param response_headers: Optional response_headers argument to
                                  specify response fields like date, size,
                                  type of file, data about server, etc.
        :param request_date: Optional request_date argument to
                              specify a different request date. Default is
                              current date.
        :param version_id: Version ID of the object.
        :param extra_query_params: Extra query parameters for advanced usage.
        :return: URL string.

        Example::
            # Get presigned URL string to download 'my-objectname' in
            # 'my-bucketname' with default expiry.
            url = minio.presigned_get_object("my-bucketname", "my-objectname")
            print(url)

            # Get presigned URL string to download 'my-objectname' in
            # 'my-bucketname' with two hours expiry.
            url = minio.presigned_get_object(
                "my-bucketname", "my-objectname", expires=timedelta(hours=2),
            )
            print(url)
        """
        return self.presigned_url(
            "GET",
            bucket_name,
            object_name,
            expires,
            response_headers=response_headers,
            request_date=request_date,
            version_id=version_id,
            extra_query_params=extra_query_params,
        )

    def presigned_put_object(self, bucket_name, object_name,
                             expires=timedelta(days=7)):
        """
        Get presigned URL of an object to upload data with expiry time and
        custom request parameters.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param expires: Expiry in seconds; defaults to 7 days.
        :return: URL string.

        Example::
            # Get presigned URL string to upload data to 'my-objectname' in
            # 'my-bucketname' with default expiry.
            url = minio.presigned_put_object("my-bucketname", "my-objectname")
            print(url)

            # Get presigned URL string to upload data to 'my-objectname' in
            # 'my-bucketname' with two hours expiry.
            url = minio.presigned_put_object(
                "my-bucketname", "my-objectname", expires=timedelta(hours=2),
            )
            print(url)
        """
        return self.presigned_url('PUT',
                                  bucket_name,
                                  object_name,
                                  expires)

    def presigned_post_policy(self, post_policy):
        """
        Get form-data of PostPolicy of an object to upload its data using POST
        method.

        :param post_policy: :class:`PostPolicy <PostPolicy>`.
        :return: :dict: contains form-data.

        Example::
            post_policy = PostPolicy()
            post_policy.set_bucket_name('bucket_name')
            post_policy.set_key_startswith('objectPrefix/')
            expires_date = datetime.utcnow()+timedelta(days=10)
            post_policy.set_expires(expires_date)

            form_data = presigned_post_policy(post_policy)
            print(form_data)
        """
        post_policy.is_valid()

        date = datetime.utcnow()
        iso8601_date = date.strftime("%Y%m%dT%H%M%SZ")
        region = self._get_bucket_region(post_policy.form_data['bucket'])
        credential_string = generate_credential_string(
            self._credentials.get().access_key, date, region)

        policy = [
            ('eq', '$x-amz-date', iso8601_date),
            ('eq', '$x-amz-algorithm', _SIGN_V4_ALGORITHM),
            ('eq', '$x-amz-credential', credential_string),
        ]
        if self._session_token:
            policy.append(('eq', '$x-amz-security-token', self._session_token))

        post_policy_base64 = post_policy.base64(extras=policy)
        signature = post_presign_signature(date, region,
                                           self._credentials.get().secret_key,
                                           post_policy_base64)
        form_data = {
            'policy': post_policy_base64,
            'x-amz-algorithm': _SIGN_V4_ALGORITHM,
            'x-amz-credential': credential_string,
            'x-amz-date': iso8601_date,
            'x-amz-signature': signature,
        }
        if self._session_token:
            form_data['x-amz-security-token'] = self._session_token

        post_policy.form_data.update(form_data)
        url_str = get_target_url(self._endpoint_url,
                                 bucket_name=post_policy.form_data['bucket'],
                                 bucket_region=region)
        return (url_str, post_policy.form_data)

    # All private functions below.
    def _get_partial_object(self, bucket_name, object_name,
                            offset=0, length=0, request_headers=None,
                            sse=None, version_id=None,
                            extra_query_params=None):
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
        is_valid_sse_c_object(sse)
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        headers = request_headers or {}

        if offset or length:
            headers['Range'] = 'bytes={}-{}'.format(
                offset, offset + length - 1 if length else "")

        if sse:
            headers.update(sse.headers())

        if version_id:
            if extra_query_params:
                extra_query_params["versionId"] = version_id
            else:
                extra_query_params = {"versionId": version_id}

        return self._url_open(
            "GET",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            preload_content=False,
            query=extra_query_params,
        )

    def _do_put_object(self, bucket_name, object_name, part_data,
                       part_size, upload_id='', part_number=0,
                       metadata=None, sse=None, progress=None):
        """
        Initiate a multipart PUT operation for a part number
        or single PUT object.

        :param bucket_name: Bucket name for the multipart request.
        :param object_name: Object name for the multipart request.
        :param part_metadata: Part-data and metadata for the multipart request.
        :param upload_id: Upload id of the multipart request [OPTIONAL].
        :param part_number: Part number of the data to be uploaded [OPTIONAL].
        :param metadata: Any additional metadata to be uploaded along
           with your object.
        :param progress: A progress object
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        # Accept only bytes - otherwise we need to know how to encode
        # the data to bytes before storing in the object.
        if not isinstance(part_data, bytes):
            raise ValueError('Input data must be bytes type')

        headers = {
            'Content-Length': part_size,
        }

        md5_base64 = ''
        sha256_hex = _UNSIGNED_PAYLOAD
        if self._is_ssl:
            md5_base64 = get_md5_base64digest(part_data)
        else:
            sha256_hex = get_sha256_hexdigest(part_data)

        if md5_base64:
            headers['Content-Md5'] = md5_base64

        if metadata:
            headers.update(metadata)

        query = {}
        if part_number > 0 and upload_id:
            query = {
                'uploadId': upload_id,
                'partNumber': str(part_number),
            }
            # Encryption headers for multipart uploads should
            # be set only in the case of SSE-C.
            if sse and isinstance(sse, SseCustomerKey):
                headers.update(sse.headers())
        elif sse:
            headers.update(sse.headers())

        response = self._url_open(
            'PUT',
            bucket_name=bucket_name,
            object_name=object_name,
            query=query,
            headers=headers,
            body=io.BytesIO(part_data),
            content_sha256=sha256_hex
        )

        if progress:
            # Update the 'progress' object with uploaded 'part_size'.
            progress.update(part_size)
        return (
            response.headers['etag'].replace('"', ''),
            response.headers.get("x-amz-version-id"),
        )

    def _upload_part_routine(self, part_info):
        """ Upload part."""
        (bucket_name, object_name, upload_id, part_number,
         part_data, sse, progress) = part_info
        # Initiate multipart put.
        vals = self._do_put_object(bucket_name, object_name, part_data,
                                   len(part_data), upload_id,
                                   part_number, sse=sse, progress=progress)
        return part_number, vals[0], len(part_data)

    def _stream_put_object(self, bucket_name, object_name,
                           data, content_size,
                           metadata=None, sse=None,
                           progress=None, part_size=MIN_PART_SIZE):
        """
        Streaming multipart upload operation.

        :param bucket_name: Bucket name of the multipart upload.
        :param object_name: Object name of the multipart upload.
        :param content_size: Total size of the content to be uploaded.
        :param content_type: Content type of of the multipart upload.
           Defaults to 'application/octet-stream'.
        :param metadata: Any additional metadata to be uploaded along
           with your object.
        :param progress: A progress object
        :param part_size: Multipart part size
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)
        if not callable(getattr(data, 'read')):
            raise ValueError(
                'Invalid input data does not implement'
                ' a callable read() method'
            )

        # get upload id.
        upload_id = self._new_multipart_upload(bucket_name, object_name,
                                               metadata, sse)

        # Initialize variables
        total_uploaded = 0
        uploaded_parts = {}

        # Calculate optimal part info.
        total_parts_count, part_size, last_part_size = optimal_part_info(
            content_size, part_size)

        # Instantiate a thread pool with 3 worker threads
        pool = ThreadPool(_PARALLEL_UPLOADERS)
        pool.start_parallel()

        # Generate new parts and upload <= current_part_size until
        # part_number reaches total_parts_count calculated for the
        # given size. Additionally part_manager() also provides
        # md5digest and sha256digest for the partitioned data.
        for part_number in range(1, total_parts_count + 1):
            current_part_size = (part_size if part_number < total_parts_count
                                 else last_part_size)

            part_data = read_full(data, current_part_size)
            pool.add_task(self._upload_part_routine, (
                bucket_name, object_name, upload_id, part_number, part_data,
                sse, progress))

        try:
            upload_result = pool.result()
        except:
            # Any exception that occurs sends an abort on the
            # on-going multipart operation.
            self._remove_incomplete_upload(bucket_name,
                                           object_name,
                                           upload_id)
            raise

        # Update uploaded_parts with the part uploads result
        # and check total uploaded data.
        while not upload_result.empty():
            part_number, etag, total_read = upload_result.get()
            uploaded_parts[part_number] = UploadPart(bucket_name,
                                                     object_name,
                                                     upload_id,
                                                     part_number,
                                                     etag,
                                                     None,
                                                     total_read)

            total_uploaded += total_read

        if total_uploaded != content_size:
            msg = 'Data uploaded {0} is not equal input size ' \
                  '{1}'.format(total_uploaded, content_size)
            # cleanup incomplete upload upon incorrect upload
            # automatically
            self._remove_incomplete_upload(bucket_name,
                                           object_name,
                                           upload_id)
            raise InvalidSizeError(msg)

        # Complete all multipart transactions if possible.
        try:
            result = self._complete_multipart_upload(bucket_name,
                                                     object_name,
                                                     upload_id,
                                                     uploaded_parts)
        except:
            # Any exception that occurs sends an abort on the
            # on-going multipart operation.
            self._remove_incomplete_upload(bucket_name,
                                           object_name,
                                           upload_id)
            raise
        return result[0].etag, result[1]

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
                              metadata=None, sse=None):
        """
        Initialize new multipart upload request.

        :param bucket_name: Bucket name of the new multipart request.
        :param object_name: Object name of the new multipart request.
        :param metadata: Additional new metadata for the new object.
        :return: Returns an upload id.
        """
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)

        headers = {}
        if metadata:
            headers.update(metadata)
        if sse:
            headers.update(sse.headers())

        response = self._url_open('POST', bucket_name=bucket_name,
                                  object_name=object_name,
                                  query={'uploads': ''},
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
        is_valid_bucket_name(bucket_name, False)
        is_non_empty_string(object_name)
        is_non_empty_string(upload_id)

        # Order uploaded parts as required by S3 specification
        ordered_parts = []
        for part in sorted(uploaded_parts.keys()):
            ordered_parts.append(uploaded_parts[part])

        data = marshal_complete_multipart(ordered_parts)
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
        return (
            parse_multipart_upload_result(response.data),
            response.headers.get("x-amz-version-id"),
        )

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

        region = self._region or self._region_map.get(bucket_name)
        if not region:
            region = self._get_bucket_location(bucket_name)
            self._region_map[bucket_name] = region
        return region

    def _get_bucket_location(self, bucket_name):
        """
        Get bucket location.

        :param bucket_name: Fetches location of the Bucket name.
        :return: location of bucket name is returned.
        """
        # Region is set override.
        if self._region:
            return self._region

        # For anonymous requests no need to get bucket location.
        if not (self._credentials.get().access_key and
                self._credentials.get().secret_key):
            return 'us-east-1'

        method = 'GET'
        url = self._endpoint_url + '/' + bucket_name + '?location='

        # Get signature headers if any.
        headers = sign_v4(method, url, "us-east-1",
                          {},
                          self._credentials,
                          None, datetime.utcnow())

        if self._trace_output_stream:
            dump_http(method, url, headers, None,
                      self._trace_output_stream)

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

    def get_assume_role_creds(self, arn=None, session_name=None,
                              policy=None, duration=None):
        """
        A callback to retrieve assume role credentials
        """
        query = {
            "Action": "AssumeRole",
            "Version": "2011-06-15",
            "RoleArn": arn or "arn:xxx:xxx:xxx:xxxx",
            "RoleSessionName": session_name or "anything",
        }

        # Add optional elements to the request
        if policy:
            query["Policy"] = policy

        if duration:
            query["DurationSeconds"] = str(duration)

        url = self._endpoint_url + "/"
        content = urlencode(query)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "User-Agent": self._user_agent
        }

        # Create signature headers
        content_sha256_hex = get_sha256_hexdigest(content)
        signed_headers = sign_v4(
            "POST",
            url,
            "us-east-1",
            headers,
            self._credentials,
            content_sha256=content_sha256_hex,
            request_datetime=datetime.utcnow(),
            service_name="sts"
        )
        response = self._http.urlopen(
            "POST",
            url,
            body=content,
            headers=signed_headers,
            preload_content=True
        )

        if response.status != 200:
            raise ResponseError(response, "POST").get_exception()

        # Parse the XML Response - getting the credentials as a Values instance.
        return parse_assume_role(response.data)

    def _url_open(self, method, bucket_name=None, object_name=None,
                  query=None, body=None, headers=None, content_sha256=None,
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
        if headers:
            fold_case_headers.update(headers)

        # Get bucket region.
        region = self._get_bucket_region(bucket_name)

        # Construct target url.
        url = get_target_url(self._endpoint_url, bucket_name=bucket_name,
                             object_name=object_name, bucket_region=region,
                             query=query)

        # Get signature headers if any.
        headers = sign_v4(method, url, region,
                          fold_case_headers,
                          self._credentials,
                          content_sha256, datetime.utcnow())

        if self._trace_output_stream:
            dump_http(method, url, headers, None,
                      self._trace_output_stream)

        response = self._http.urlopen(method, url,
                                      body=body,
                                      headers=headers,
                                      preload_content=preload_content)

        if self._trace_output_stream:
            dump_http(method, url, fold_case_headers, response,
                      self._trace_output_stream)

        if response.status not in [200, 204, 206]:
            # Upon any response error invalidate the region cache
            # proactively for the bucket name.
            self._delete_bucket_region(bucket_name)

            # In case we did not preload_content, we need to release
            # the connection:
            if not preload_content:
                response.release_conn()

            if method in ['DELETE', 'GET', 'HEAD', 'POST', 'PUT']:
                raise ResponseError(response,
                                    method,
                                    bucket_name,
                                    object_name).get_exception()

            raise ValueError('Unsupported method returned'
                             ' error: {0}'.format(response.status))

        return response

    def _list_objects(  # pylint: disable=too-many-arguments,too-many-branches
            self,
            bucket_name,
            continuation_token=None,  # listV2 only
            delimiter=None,  # all
            encoding_type=None,  # all
            fetch_owner=None,  # listV2 only
            include_user_meta=None,  # MinIO specific listV2.
            max_keys=None,  # all
            prefix=None,  # all
            start_after=None,  # all: v1:marker, versioned:key_marker
            version_id_marker=None,  # versioned
            use_version1=False,
            include_version=False,
    ):
        """
        List objects optionally including versions.
        Note: Its required to send empty values to delimiter/prefix and 1000 to
        max-keys when not provided for server-side bucket policy evaluation to
        succeed; otherwise AccessDenied error will be returned for such
        policies.
        """

        is_valid_bucket_name(bucket_name, False)

        if version_id_marker:
            include_version = True

        is_truncated = True
        while is_truncated:
            query = {}
            if include_version:
                query["versions"] = ""
            elif not use_version1:
                query["list-type"] = "2"

            if not include_version and not use_version1:
                if continuation_token:
                    query["continuation-token"] = continuation_token
                if fetch_owner:
                    query["fetch-owner"] = "true"
                if include_user_meta:
                    query["user-metadata"] = "true"
            query["delimiter"] = delimiter or ""
            if encoding_type:
                query["encoding-type"] = encoding_type
            query["max-keys"] = str(max_keys or 1000)
            query["prefix"] = prefix or ""
            if start_after:
                if include_version:
                    query["key-marker"] = start_after
                elif use_version1:
                    query["marker"] = start_after
                else:
                    query["start-after"] = start_after
            if version_id_marker:
                query["version-id-marker"] = version_id_marker

            response = self._url_open(
                method="GET",
                bucket_name=bucket_name,
                query=query,
            )

            if include_version:
                objects, is_truncated, start_after, version_id_marker = (
                    parse_list_object_versions(response.data, bucket_name)
                )
            elif use_version1:
                objects, is_truncated, start_after = parse_list_objects(
                    response.data,
                    bucket_name,
                )
            else:
                objects, is_truncated, continuation_token = (
                    parse_list_objects_v2(response.data, bucket_name)
                )

            for obj in objects:
                yield obj
