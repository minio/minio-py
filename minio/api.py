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

import itertools
import json
import os
import platform
from datetime import datetime, timedelta
from threading import Thread
from urllib.parse import urlunsplit
from xml.etree import ElementTree as ET

import certifi
import dateutil.parser
import urllib3

from . import __title__, __version__
from .commonconfig import Tags
from .credentials import StaticProvider
from .definitions import BaseURL, Object, ObjectWriteResult, Part
from .error import InvalidResponseError, S3Error, ServerError
from .helpers import (amzprefix_user_metadata, check_bucket_name,
                      check_non_empty_string, check_sse, check_ssec,
                      get_part_info, headers_to_strings, is_amz_header,
                      is_supported_header, is_valid_notification_config,
                      is_valid_policy_type, makedirs, md5sum_hash, quote,
                      read_part_data, sha256_hash, strptime_rfc3339)
from .lifecycleconfig import LifecycleConfig
from .parsers import (parse_error_response, parse_get_bucket_notification,
                      parse_list_buckets, parse_list_multipart_uploads,
                      parse_list_object_versions, parse_list_objects,
                      parse_list_objects_v2, parse_list_parts,
                      parse_multi_delete_response,
                      parse_multipart_upload_result,
                      parse_new_multipart_upload)
from .replicationconfig import ReplicationConfig
from .select import SelectObjectReader
from .selectrequest import SelectRequest
from .signer import (AMZ_DATE_FORMAT, SIGN_V4_ALGORITHM, get_credential_string,
                     post_presign_v4, presign_v4, sign_v4_s3)
from .sse import SseCustomerKey
from .tagging import Tagging
from .thread_pool import ThreadPool
from .versioningconfig import VersioningConfig
from .xml import Element, SubElement, findtext, getbytes, marshal, unmarshal
from .xml_marshal import (marshal_bucket_notifications,
                          xml_marshal_bucket_encryption,
                          xml_marshal_delete_objects, xml_to_dict)

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


_DEFAULT_USER_AGENT = "MinIO ({os}; {arch}) {lib}/{ver}".format(
    os=platform.system(), arch=platform.machine(),
    lib=__title__, ver=__version__,
)


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
    :param credentials: Credentials provider of your account in S3 service.
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
        # Validate http client has correct base class.
        if http_client and not isinstance(
                http_client,
                urllib3.poolmanager.PoolManager):
            raise ValueError(
                "HTTP client should be instance of "
                "`urllib3.poolmanager.PoolManager`"
            )

        self._region_map = dict()
        self._base_url = BaseURL(
            ("https://" if secure else "http://") + endpoint,
            region,
        )
        self._user_agent = _DEFAULT_USER_AGENT
        self._trace_stream = None
        if access_key:
            credentials = StaticProvider(access_key, secret_key, session_token)
        self._provider = credentials

        # Load CA certificates from SSL_CERT_FILE file if set
        ca_certs = os.environ.get('SSL_CERT_FILE') or certifi.where()
        self._http = http_client or urllib3.PoolManager(
            timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
            maxsize=10,
            cert_reqs='CERT_REQUIRED',
            ca_certs=ca_certs,
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def _handle_redirect_response(
            self, method, bucket_name, response, retry=False,
    ):
        """
        Handle redirect response indicates whether retry HEAD request
        on failure.
        """
        code, message = {
            301: ("PermanentRedirect", "Moved Permanently"),
            307: ("Redirect", "Temporary redirect"),
            400: ("BadRequest", "Bad request"),
        }.get(response.status, (None, None))
        region = response.getheader("x-amz-bucket-region")
        if message and region:
            message += "; use region " + region

        if (
                retry and region and method == "HEAD" and bucket_name and
                self._region_map.get(bucket_name)
        ):
            code, message = ("RetryHead", None)

        return code, message

    def _build_headers(self, host, headers, body, creds):
        """Build headers with given parameters."""
        headers = headers or {}
        md5sum_added = headers.get("Content-MD5")
        headers["Host"] = host
        headers["User-Agent"] = self._user_agent
        sha256 = None
        md5sum = None

        if body:
            headers["Content-Length"] = str(len(body))
        if creds:
            if self._base_url.is_https:
                sha256 = "UNSIGNED-PAYLOAD"
                md5sum = None if md5sum_added else md5sum_hash(body)
            else:
                sha256 = sha256_hash(body)
        else:
            md5sum = None if md5sum_added else md5sum_hash(body)
        if md5sum:
            headers["Content-MD5"] = md5sum
        if sha256:
            headers["x-amz-content-sha256"] = sha256
        if creds and creds.session_token:
            headers["X-Amz-Security-Token"] = creds.session_token
        date = datetime.utcnow()
        headers["x-amz-date"] = date.strftime(AMZ_DATE_FORMAT)
        return headers, date

    def _url_open(  # pylint: disable=too-many-branches
            self,
            method,
            region,
            bucket_name=None,
            object_name=None,
            body=None,
            headers=None,
            query_params=None,
            preload_content=True,
    ):
        """Execute HTTP request."""
        creds = self._provider.retrieve() if self._provider else None
        trace_body = isinstance(body, str)
        body = body.encode() if trace_body else body
        url = self._base_url.build(
            method,
            region,
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
        )
        headers, date = self._build_headers(url.netloc, headers, body, creds)
        if creds:
            headers = sign_v4_s3(
                method,
                url,
                region,
                headers,
                creds,
                headers.get("x-amz-content-sha256"),
                date,
            )

        if self._trace_stream:
            self._trace_stream.write("---------START-HTTP---------\n")
            self._trace_stream.write(
                "{0} {1}{2}{3} HTTP/1.1\n".format(
                    method,
                    url.path,
                    "?" if url.query else "",
                    url.query or "",
                ),
            )
            self._trace_stream.write(
                headers_to_strings(headers, titled_key=True),
            )
            self._trace_stream.write("\n")
            if trace_body:
                self._trace_stream.write(body.decode())
            self._trace_stream.write("\n")

        response = self._http.urlopen(
            method,
            urlunsplit(url),
            body=body,
            headers=headers,
            preload_content=preload_content,
        )

        if self._trace_stream:
            self._trace_stream.write("HTTP/1.1 {0}\n".format(response.status))
            self._trace_stream.write(
                headers_to_strings(response.getheaders()),
            )
            self._trace_stream.write("\n")

        if response.status in [200, 204, 206]:
            if self._trace_stream:
                self._trace_stream.write("----------END-HTTP----------\n")
            return response

        response.read(cache_content=True)
        if not preload_content:
            response.release_conn()

        if self._trace_stream and method != "HEAD" and response.data:
            self._trace_stream.write(response.data.decode())
            self._trace_stream.write("\n")

        if (
                method != "HEAD" and
                "application/xml" not in response.getheader(
                    "content-type", "",
                ).split(";")
        ):
            if self._trace_stream:
                self._trace_stream.write("----------END-HTTP----------\n")
            raise InvalidResponseError(
                response.status,
                response.getheader("content-type"),
                response.data.decode() if response.data else None,
            )

        if not response.data and method != "HEAD":
            if self._trace_stream:
                self._trace_stream.write("----------END-HTTP----------\n")
            raise InvalidResponseError(
                response.status,
                response.getheader("content-type"),
                None,
            )

        response_error = (
            parse_error_response(response)
            if response.data else None
        )

        if self._trace_stream:
            self._trace_stream.write("----------END-HTTP----------\n")

        error_map = {
            301: lambda: self._handle_redirect_response(
                method, bucket_name, response, True,
            ),
            307: lambda: self._handle_redirect_response(
                method, bucket_name, response, True,
            ),
            400: lambda: self._handle_redirect_response(
                method, bucket_name, response, True,
            ),
            403: lambda: ("AccessDenied", "Access denied"),
            404: lambda: (
                ("NoSuchKey", "Object does not exist")
                if object_name
                else ("NoSuchBucket", "Bucket does not exist")
                if bucket_name
                else ("ResourceNotFound", "Request resource not found")
            ),
            405: lambda: (
                "MethodNotAllowed",
                "The specified method is not allowed against this resource",
            ),
            409: lambda: (
                ("NoSuchBucket", "Bucket does not exist")
                if bucket_name
                else ("ResourceConflict", "Request resource conflicts"),
            ),
            501: lambda: (
                "MethodNotAllowed",
                "The specified method is not allowed against this resource",
            ),
        }

        if not response_error:
            func = error_map.get(response.status)
            code, message = func() if func else (None, None)
            if not code:
                raise ServerError(
                    "server failed with HTTP status code {}".format(
                        response.status,
                    ),
                )
            response_error = S3Error(
                code,
                message,
                url.path,
                response.getheader("x-amz-request-id"),
                response.getheader("x-amz-id-2"),
                response,
                bucket_name=bucket_name,
                object_name=object_name,
            )

        if response_error.code in ["NoSuchBucket", "RetryHead"]:
            self._region_map.pop(bucket_name, None)

        raise response_error

    def _execute(
            self,
            method,
            bucket_name=None,
            object_name=None,
            body=None,
            headers=None,
            query_params=None,
            preload_content=True,
    ):
        """Execute HTTP request."""
        region = self._get_region(bucket_name, None)

        try:
            return self._url_open(
                method,
                region,
                bucket_name=bucket_name,
                object_name=object_name,
                body=body,
                headers=headers,
                query_params=query_params,
                preload_content=preload_content,
            )
        except S3Error as exc:
            if exc.code != "RetryHead":
                raise

        # Retry only once on RetryHead error.
        try:
            return self._url_open(
                method,
                region,
                bucket_name=bucket_name,
                object_name=object_name,
                body=body,
                headers=headers,
                query_params=query_params,
                preload_content=preload_content,
            )
        except S3Error as exc:
            if exc.code != "RetryHead":
                raise

            code, message = self._handle_redirect_response(
                method, bucket_name, exc.response,
            )
            raise exc.copy(code, message)

    def _get_region(self, bucket_name, region):
        """
        Return region of given bucket either from region cache or set in
        constructor.
        """

        if region:
            # Error out if region does not match with region passed via
            # constructor.
            if self._base_url.region and self._base_url.region != region:
                raise ValueError(
                    "region must be {0}, but passed {1}".format(
                        self._base_url.region, region,
                    ),
                )
            return region

        if self._base_url.region:
            return self._base_url.region

        if not bucket_name or not self._provider:
            return "us-east-1"

        region = self._region_map.get(bucket_name)
        if region:
            return region

        # Execute GetBucketLocation REST API to get region of the bucket.
        response = self._url_open(
            "GET",
            "us-east-1",
            bucket_name=bucket_name,
            query_params={"location": ""},
        )

        element = ET.fromstring(response.data.decode())
        if not element.text:
            region = "us-east-1"
        elif element.text == "EU":
            region = "eu-west-1"
        else:
            region = element.text

        self._region_map[bucket_name] = region
        return region

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
        self._trace_stream = stream

    def trace_off(self):
        """
        Disable HTTP trace.
        """
        self._trace_stream = None

    def enable_accelerate_endpoint(self):
        """Enables accelerate endpoint for Amazon S3 endpoint."""
        self._base_url.accelerate_host_flag = True

    def disable_accelerate_endpoint(self):
        """Disables accelerate endpoint for Amazon S3 endpoint."""
        self._base_url.accelerate_host_flag = False

    def enable_dualstack_endpoint(self):
        """Enables dualstack endpoint for Amazon S3 endpoint."""
        self._base_url.dualstack_host_flag = True

    def disable_dualstack_endpoint(self):
        """Disables dualstack endpoint for Amazon S3 endpoint."""
        self._base_url.dualstack_host_flag = False

    def enable_virtual_style_endpoint(self):
        """Enables virtual style endpoint."""
        self._base_url.virtual_style_flag = True

    def disable_virtual_style_endpoint(self):
        """Disables virtual style endpoint."""
        self._base_url.virtual_style_flag = False

    def select_object_content(self, bucket_name, object_name, request):
        """
        Select content of an object by SQL expression.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param request: :class:`SelectRequest <SelectRequest>` object.
        :return: A reader contains requested records and progress information.

        Example::
            request = SelectRequest(
                "select * from s3object",
                CSVInputSerialization(),
                CSVOutputSerialization(),
                request_progress=True,
            )
            data = client.select_object_content('foo', 'test.csv', request)
        """
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        if not isinstance(request, SelectRequest):
            raise ValueError("request must be SelectRequest type")
        body = marshal(request)
        response = self._execute(
            "POST",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"select": "", "select-type": "2"},
            preload_content=False,
        )
        return SelectObjectReader(response)

    def make_bucket(self, bucket_name, location=None, object_lock=False):
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
        check_bucket_name(bucket_name, True)
        if self._base_url.region:
            # Error out if region does not match with region passed via
            # constructor.
            if location and self._base_url.region != location:
                raise ValueError(
                    "region must be {0}, but passed {1}".format(
                        self._base_url.region, location,
                    ),
                )
        location = location or "us-east-1"
        headers = (
            {"x-amz-bucket-object-lock-enabled": "true"}
            if object_lock else None
        )

        body = None
        if location != "us-east-1":
            element = Element("CreateBucketConfiguration")
            SubElement(element, "LocationConstraint", location)
            body = marshal(element)
        self._url_open(
            "PUT",
            location,
            bucket_name=bucket_name,
            body=body,
            headers=headers,
        )
        self._region_map[bucket_name] = location

    def list_buckets(self):
        """
        List information of all accessible buckets.

        :return: An iterator contains bucket information.

        Example::
            bucket_list = minio.list_buckets()
            for bucket in bucket_list:
                print(bucket.name, bucket.created_date)
        """

        response = self._execute("GET")
        return parse_list_buckets(response.data)

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
        check_bucket_name(bucket_name)
        try:
            self._execute("HEAD", bucket_name)
            return True
        except S3Error as exc:
            if exc.code != "NoSuchBucket":
                raise
        return False

    def remove_bucket(self, bucket_name):
        """
        Remove an empty bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.remove_bucket("my-bucketname")
        """
        check_bucket_name(bucket_name)
        self._execute("DELETE", bucket_name)
        self._region_map.pop(bucket_name, None)

    def get_bucket_policy(self, bucket_name):
        """
        Get bucket policy configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: Bucket policy configuration as JSON string.

        Example::
            config = minio.get_bucket_policy("my-bucketname")
        """
        check_bucket_name(bucket_name)
        response = self._execute(
            "GET", bucket_name, query_params={"policy": ""},
        )
        return response.data.decode()

    def delete_bucket_policy(self, bucket_name):
        """
        Delete bucket policy configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_policy("my-bucketname")
        """
        check_bucket_name(bucket_name)
        self._execute("DELETE", bucket_name, query_params={"policy": ""})

    def set_bucket_policy(self, bucket_name, policy):
        """
        Set bucket policy configuration to a bucket.

        :param bucket_name: Name of the bucket.
        :param policy: Bucket policy configuration as JSON string.

        Example::
            minio.set_bucket_policy("my-bucketname", config)
        """
        check_bucket_name(bucket_name)
        is_valid_policy_type(policy)
        self._execute(
            "PUT",
            bucket_name,
            body=policy,
            headers={"Content-MD5": md5sum_hash(policy)},
            query_params={"policy": ""},
        )

    def get_bucket_notification(self, bucket_name):
        """
        Get notification configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: Notification configuration.

        Example::
            config = minio.get_bucket_notification("my-bucketname")
        """
        check_bucket_name(bucket_name)
        response = self._execute(
            "GET", bucket_name, query_params={"notification": ""},
        )
        return parse_get_bucket_notification(response.data.decode())

    def _set_bucket_notification(self, bucket_name, notifications):
        """Execute SetBucketNotification API."""
        body = marshal_bucket_notifications(notifications)
        self._execute(
            "PUT",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"notification": ""},
        )

    def set_bucket_notification(self, bucket_name, notifications):
        """
        Set notification configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :param notifications: Notification configuration to be set.

        Example::
            minio.set_bucket_notification("my-bucketname", config)
        """
        check_bucket_name(bucket_name)
        is_valid_notification_config(notifications)
        return self._set_bucket_notification(bucket_name, notifications)

    def remove_all_bucket_notification(self, bucket_name):
        """
        Remove notification configuration of a bucket. On success, S3 service
        stops notification of events previously set of the bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.remove_all_bucket_notification("my-bucketname")
        """
        check_bucket_name(bucket_name)
        return self._set_bucket_notification(bucket_name, {})

    def put_bucket_encryption(self, bucket_name, enc_config):
        """
        Set encryption configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :param enc_config: Encryption configuration as dictionary to be set.

        Example::
            minio.put_bucket_encryption("my-bucketname", config)
        """
        check_bucket_name(bucket_name)

        # 'Rule' is a list, so we need to go through each one of
        # its key/value pair and collect the encryption values.
        rules = enc_config['ServerSideEncryptionConfiguration']['Rule']
        body = xml_marshal_bucket_encryption(rules)
        self._execute(
            "PUT",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"encryption": ""},
        )

    def get_bucket_encryption(self, bucket_name):
        """
        Get encryption configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: Encryption configuration.

        Example::
            config = minio.get_bucket_encryption("my-bucketname")
        """
        check_bucket_name(bucket_name)
        response = self._execute(
            "GET",
            bucket_name,
            query_params={"encryption": ""},
        )
        return xml_to_dict(response.data.decode())

    def delete_bucket_encryption(self, bucket_name):
        """
        Delete encryption configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_encryption("my-bucketname")
        """
        check_bucket_name(bucket_name)
        self._execute(
            "DELETE",
            bucket_name,
            query_params={"encryption": ""},
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
        check_bucket_name(bucket_name)
        if self._base_url.is_aws_host:
            raise ValueError(
                "ListenBucketNotification API is not supported in Amazon S3",
            )

        while True:
            response = self._execute(
                "GET",
                bucket_name,
                query_params={
                    "prefix": prefix or "",
                    "suffix": suffix or "",
                    "events": events,
                },
                preload_content=False,
            )

            try:
                for line in response.stream():
                    line = line.strip()
                    if not line:
                        continue
                    if hasattr(line, 'decode'):
                        line = line.decode()
                    event = json.loads(line)
                    if event['Records']:
                        yield event
            except JSONDecodeError:
                pass  # Ignore this exception.
            finally:
                response.close()
                response.release_conn()

    def set_bucket_versioning(self, bucket_name, config):
        """
        Set versioning configuration to a bucket.

        :param bucket_name: Name of the bucket.
        :param config: :class:`VersioningConfig <VersioningConfig>`.

        Example::
            minio.set_bucket_versioning(
                "my-bucketname", VersioningConfig(ENABLED),
            )
        """
        check_bucket_name(bucket_name)
        if not isinstance(config, VersioningConfig):
            raise ValueError("config must be VersioningConfig type")
        body = marshal(config)
        self._execute(
            "PUT",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"versioning": ""},
        )

    def get_bucket_versioning(self, bucket_name):
        """
        Get versioning configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: :class:`VersioningConfig <VersioningConfig>`.

        Example::
            config minio.get_bucket_versioning("my-bucketname")
            print(config.status)
        """
        check_bucket_name(bucket_name)
        response = self._execute(
            "GET",
            bucket_name,
            query_params={"versioning": ""},
        )
        return unmarshal(VersioningConfig, response.data.decode())

    def fput_object(self, bucket_name, object_name, file_path,
                    content_type='application/octet-stream',
                    metadata=None, sse=None, progress=None,
                    part_size=0):
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
                    extra_query_params=None, tmp_file_path=None):
        """
        Downloads data of an object to file.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param file_path: Name of file to download.
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
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)

        if os.path.isdir(file_path):
            raise ValueError("file {0} is a directory".format(file_path))

        # Create top level directory if needed.
        makedirs(os.path.dirname(file_path))

        stat = self.stat_object(
            bucket_name,
            object_name,
            sse,
            version_id=version_id,
        )

        # Write to a temporary file "file_path.part.minio" before saving.
        tmp_file_path = (
            tmp_file_path or file_path + "." + stat.etag + ".part.minio"
        )
        try:
            tmp_file_stat = os.stat(tmp_file_path)
        except IOError:
            tmp_file_stat = None  # Ignore this error.
        offset = tmp_file_stat.st_size if tmp_file_stat else 0
        if offset > stat.size:
            os.remove(tmp_file_path)
            offset = 0

        try:
            response = self.get_object(
                bucket_name,
                object_name,
                offset=offset,
                request_headers=request_headers,
                sse=sse,
                version_id=version_id,
                extra_query_params=extra_query_params,
            )
            with open(tmp_file_path, "ab") as tmp_file:
                for data in response.stream(amt=1024*1024):
                    tmp_file.write(data)
            if os.path.exists(file_path):
                os.remove(file_path)  # For windows compatibility.
            os.rename(tmp_file_path, file_path)
            return stat
        finally:
            if response:
                response.close()
                response.release_conn()

    def get_object(self, bucket_name, object_name, offset=0, length=0,
                   request_headers=None, sse=None, version_id=None,
                   extra_query_params=None):
        """
        Get data of an object. Returned response should be closed after use to
        release network resources. To reuse the connection, it's required to
        call `response.release_conn()` explicitly.

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
            // Get entire object data.
            try:
                response = minio.get_object('foo', 'bar')
                // Read data from response.
            finally:
                response.close()
                response.release_conn()

            // Get object data for offset/length.
            try:
                response = minio.get_object('foo', 'bar', 2, 4)
                // Read data from response.
            finally:
                response.close()
                response.release_conn()
        """
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        check_ssec(sse)

        headers = sse.headers() if sse else {}
        headers.update(request_headers or {})

        if offset or length:
            headers['Range'] = 'bytes={}-{}'.format(
                offset, offset + length - 1 if length else "")

        if version_id:
            extra_query_params = extra_query_params or {}
            extra_query_params["versionId"] = version_id

        return self._execute(
            "GET",
            bucket_name,
            object_name,
            headers=headers,
            query_params=extra_query_params,
            preload_content=False,
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
        :return: :class:`ObjectWriteResult <ObjectWriteResult>` object.

        Example::
            minio.copy_object(
                "my-bucketname",
                "my-objectname",
                "my-source-bucketname/my-source-objectname",
            )
            minio.copy_object(
                "my-bucketname",
                "my-objectname",
                "my-source-bucketname/my-source-objectname"
                "?versionId=b6602757-7c9c-449b-937f-fed504d04c94",
            )
        """
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        check_non_empty_string(object_source)
        check_ssec(source_sse)
        check_sse(sse)

        # Preserving the user-defined metadata in headers
        if metadata:
            headers = amzprefix_user_metadata(metadata)
            headers["x-amz-metadata-directive"] = "REPLACE"
        else:
            headers = {}
        if conditions:
            headers.update(conditions)
        headers.update(source_sse.copy_headers() if source_sse else {})
        headers.update(sse.headers() if sse else {})
        headers['X-Amz-Copy-Source'] = quote(object_source)
        response = self._execute(
            "PUT",
            bucket_name,
            object_name=object_name,
            headers=headers,
        )
        element = ET.fromstring(response.data.decode())
        etag = findtext(element, "ETag")
        if etag:
            etag = etag.replace('"', "")
        last_modified = findtext(element, "LastModified")
        if last_modified:
            last_modified = strptime_rfc3339(last_modified)
        return ObjectWriteResult(
            bucket_name,
            object_name,
            response.getheader("x-amz-version-id"),
            etag,
            last_modified,
        )

    def _abort_multipart_upload(self, bucket_name, object_name, upload_id):
        """Execute AbortMultipartUpload S3 API."""
        self._execute(
            "DELETE",
            bucket_name,
            object_name,
            query_params={'uploadId': upload_id},
        )

    def _complete_multipart_upload(
            self, bucket_name, object_name, upload_id, parts,
    ):
        """Execute CompleteMultipartUpload S3 API."""
        element = Element("CompleteMultipartUpload")
        for part in parts:
            tag = SubElement(element, "Part")
            SubElement(tag, "PartNumber", str(part.part_number))
            SubElement(tag, "ETag", '"' + part.etag + '"')
        body = getbytes(element)
        response = self._execute(
            "POST",
            bucket_name,
            object_name,
            body=body,
            headers={
                "Content-Type": 'application/xml',
                "Content-MD5": md5sum_hash(body),
            },
            query_params={'uploadId': upload_id},
        )
        return (
            parse_multipart_upload_result(response.data),
            response.getheader("x-amz-version-id"),
        )

    def _create_multipart_upload(self, bucket_name, object_name, headers):
        """Execute CreateMultipartUpload S3 API."""
        if not headers.get("Content-Type"):
            headers["Content-Type"] = "application/octet-stream"
        response = self._execute(
            "POST",
            bucket_name,
            object_name,
            headers=headers,
            query_params={"uploads": ""},
        )
        return parse_new_multipart_upload(response.data)

    def _put_object(self, bucket_name, object_name, data, headers,
                    query_params=None):
        """Execute PutObject S3 API."""
        response = self._execute(
            "PUT",
            bucket_name,
            object_name,
            body=data,
            headers=headers,
            query_params=query_params,
        )
        return (
            response.getheader("etag").replace('"', ""),
            response.getheader("x-amz-version-id"),
        )

    def _upload_part(self, bucket_name, object_name, data, headers,
                     upload_id, part_number):
        """Execute UploadPart S3 API."""
        query_params = {
            "partNumber": str(part_number),
            "uploadId": upload_id,
        }
        etag, _ = self._put_object(
            bucket_name, object_name, data, headers, query_params=query_params,
        )
        return etag

    def _upload_part_task(self, args):
        """Upload_part task for ThreadPool."""
        return args[5], self._upload_part(*args)

    def put_object(  # pylint: disable=too-many-branches,too-many-statements
            self, bucket_name, object_name, data, length,
            content_type='application/octet-stream',
            metadata=None, sse=None, progress=None,
            part_size=0, num_parallel_uploads=3,
    ):
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
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        check_sse(sse)
        if not callable(getattr(data, "read")):
            raise ValueError("input data must have callable read()")
        part_size, part_count = get_part_info(length, part_size)

        if progress:
            if not isinstance(progress, Thread):
                raise TypeError("progress object must be instance of Thread")
            # Set progress bar length and object name before upload
            progress.set_meta(object_name=object_name, total_length=length)

        headers = amzprefix_user_metadata(metadata or {})
        headers["Content-Type"] = content_type or "application/octet-stream"
        headers.update(sse.headers() if sse else {})

        object_size = length
        uploaded_size = 0
        part_number = 0
        one_byte = b''
        stop = False
        upload_id = None
        parts = []
        pool = None

        try:
            while not stop:
                part_number += 1
                if part_count > 0:
                    if part_number == part_count:
                        part_size = object_size - uploaded_size
                        stop = True
                    part_data = read_part_data(
                        data, part_size, progress=progress,
                    )
                    if len(part_data) != part_size:
                        raise IOError(
                            (
                                "stream having not enough data;"
                                "expected: {0}, got: {1} bytes"
                            ).format(part_size, len(part_data))
                        )
                else:
                    part_data = read_part_data(
                        data, part_size + 1, one_byte, progress=progress,
                    )
                    # If part_data_size is less or equal to part_size,
                    # then we have reached last part.
                    if len(part_data) <= part_size:
                        part_count = part_number
                        stop = True
                    else:
                        one_byte = part_data[-1:]
                        part_data = part_data[:-1]

                uploaded_size += len(part_data)

                if part_count == 1:
                    return self._put_object(
                        bucket_name, object_name, part_data, headers,
                    )

                if not upload_id:
                    upload_id = self._create_multipart_upload(
                        bucket_name, object_name, headers,
                    )
                    if num_parallel_uploads and num_parallel_uploads > 1:
                        pool = ThreadPool(num_parallel_uploads)
                        pool.start_parallel()

                args = (
                    bucket_name, object_name, part_data,
                    sse.headers() if isinstance(sse, SseCustomerKey) else None,
                    upload_id, part_number,
                )
                if num_parallel_uploads > 1:
                    pool.add_task(self._upload_part_task, args)
                else:
                    etag = self._upload_part(*args)
                    parts.append(Part(part_number, etag))

            if pool:
                result = pool.result()
                parts = [None] * part_count
                while not result.empty():
                    part_number, etag = result.get()
                    parts[part_number-1] = Part(part_number, etag)

            result = self._complete_multipart_upload(
                bucket_name, object_name, upload_id, parts,
            )
            return result[0].etag, result[1]
        except Exception as exc:
            if upload_id:
                self._abort_multipart_upload(
                    bucket_name, object_name, upload_id,
                )
            raise exc

    def list_objects(self, bucket_name, prefix=None, recursive=False,
                     start_after=None, include_user_meta=False,
                     include_version=False, use_api_v1=False):
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
        :param use_api_v1: Flag to control to use ListObjectV1 S3 API or not.
        :return: An iterator contains object information.

        Example::
            # List objects information.
            objects = minio.list_objects('foo')
            for object in objects:
                print(object)

            # List objects information whose names starts with 'hello/'.
            objects = minio.list_objects('foo', prefix='hello/')
            for object in objects:
                print(object)

            # List objects information recursively.
            objects = minio.list_objects('foo', recursive=True)
            for object in objects:
                print(object)

            # List objects information recursively whose names starts with
            # 'hello/'.
            objects = minio.list_objects(
                'foo', prefix='hello/', recursive=True,
            )
            for object in objects:
                print(object)

            # List objects information recursively after object name
            # 'hello/world/1'.
            objects = minio.list_objects(
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
            use_api_v1=use_api_v1,
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

        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        check_ssec(sse)

        headers = sse.headers() if sse else {}
        query_params = extra_query_params or {}
        query_params.update({"versionId": version_id} if version_id else {})
        response = self._execute(
            "HEAD",
            bucket_name,
            object_name,
            headers=headers,
            query_params=query_params,
        )

        custom_metadata = {
            key: value for key, value in response.headers.items()
            if is_supported_header(key) or is_amz_header(key)
        }

        last_modified = response.getheader("last-modified")
        if last_modified:
            last_modified = dateutil.parser.parse(last_modified).timetuple()

        return Object(
            bucket_name,
            object_name,
            last_modified=last_modified,
            etag=response.getheader("etag", "").replace('"', ""),
            size=int(response.getheader("content-length", "0")),
            content_type=response.getheader("content-type"),
            metadata=custom_metadata,
            version_id=response.getheader("x-amz-version-id"),
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
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        self._execute(
            "DELETE",
            bucket_name,
            object_name,
            query_params={"versionId": version_id} if version_id else None,
        )

    def _process_remove_objects_batch(self, bucket_name, objects_batch):
        """
        Requester and response parser for remove_objects
        """
        body = xml_marshal_delete_objects(objects_batch)
        response = self._execute(
            "POST",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={'delete': ''},
        )
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
        check_bucket_name(bucket_name)
        if isinstance(objects_iter, (str, bytes)):
            raise TypeError(
                'objects_iter cannot be `str` or `bytes` instance. It must be '
                'a list, tuple or iterator of object names'
            )

        # turn list like objects into an iterator.
        objects_iter = itertools.chain(objects_iter)

        def check_name(name):
            if not isinstance(name, (str, bytes)):
                name = name[0]
            check_non_empty_string(name)
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
                yield err_result

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
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        if expires.total_seconds() < 1 or expires.total_seconds() > 604800:
            raise ValueError("expires must be between 1 second to 7 days")

        region = self._get_region(bucket_name, None)
        query_params = extra_query_params or {}
        query_params.update({"versionId": version_id} if version_id else {})
        query_params.update(response_headers or {})
        creds = self._provider.retrieve() if self._provider else None
        if creds and creds.session_token:
            query_params["X-Amz-Security-Token"] = creds.session_token
        url = self._base_url.build(
            method,
            region,
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
        )

        if creds:
            url = presign_v4(
                method,
                url,
                region,
                creds,
                request_date or datetime.utcnow(),
                int(expires.total_seconds()),
            )
        return urlunsplit(url)

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
        if not self._provider:
            raise ValueError(
                "anonymous access does not require presigned post form-data",
            )

        bucket_name = post_policy.form_data['bucket']
        region = self._get_region(bucket_name, None)
        credentials = self._provider.retrieve()
        date = datetime.utcnow()
        credential_string = get_credential_string(
            credentials.access_key, date, region,
        )
        policy = [
            ('eq', '$x-amz-date', date.strftime(AMZ_DATE_FORMAT)),
            ('eq', '$x-amz-algorithm', SIGN_V4_ALGORITHM),
            ('eq', '$x-amz-credential', credential_string),
        ]
        if credentials.session_token:
            policy.append(
                ('eq', '$x-amz-security-token', credentials.session_token),
            )
        post_policy_base64 = post_policy.base64(extras=policy)
        signature = post_presign_v4(
            post_policy_base64, credentials, date, region,
        )
        form_data = {
            'policy': post_policy_base64,
            'x-amz-algorithm': SIGN_V4_ALGORITHM,
            'x-amz-credential': credential_string,
            'x-amz-date': date.strftime(AMZ_DATE_FORMAT),
            'x-amz-signature': signature,
        }
        if credentials.session_token:
            form_data['x-amz-security-token'] = credentials.session_token
        post_policy.form_data.update(form_data)
        return (
            self._base_url.build("POST", region, bucket_name),
            post_policy.form_data,
        )

    def delete_bucket_replication(self, bucket_name):
        """
        Delete replication configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_replication("my-bucketname")
        """
        check_bucket_name(bucket_name)
        self._execute("DELETE", bucket_name, query_params={"replication": ""})

    def get_bucket_replication(self, bucket_name):
        """
        Get bucket replication configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: :class:`ReplicationConfig <ReplicationConfig>` object.

        Example::
            config = minio.get_bucket_replication("my-bucketname")
        """
        check_bucket_name(bucket_name)
        try:
            response = self._execute(
                "GET", bucket_name, query_params={"replication": ""},
            )
            return unmarshal(ReplicationConfig, response.data.decode())
        except S3Error as exc:
            if exc.code != "ReplicationConfigurationNotFoundError":
                raise
        return None

    def set_bucket_replication(self, bucket_name, config):
        """
        Set bucket replication configuration to a bucket.

        :param bucket_name: Name of the bucket.
        :param config: :class:`ReplicationConfig <ReplicationConfig>` object.

        Example::
            config = ReplicationConfig(
                "REPLACE-WITH-ACTUAL-ROLE",
                [
                    Rule(
                        Destination(
                            "REPLACE-WITH-ACTUAL-DESTINATION-BUCKET-ARN",
                        ),
                        ENABLED,
                        delete_marker_replication=DeleteMarkerReplication(
                            DISABLED,
                        ),
                        rule_filter=Filter(
                            AndOperator(
                                "TaxDocs",
                                {"key1": "value1", "key2": "value2"},
                            ),
                        ),
                        rule_id="rule1",
                        priority=1,
                    ),
                ],
            )
            minio.set_bucket_replication("my-bucketname", config)
        """
        check_bucket_name(bucket_name)
        if not isinstance(config, ReplicationConfig):
            raise ValueError("config must be ReplicationConfig type")
        body = marshal(config)
        self._execute(
            "PUT",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"replication": ""},
        )

    def delete_bucket_lifecycle(self, bucket_name):
        """
        Delete notification configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_lifecycle("my-bucketname")
        """
        check_bucket_name(bucket_name)
        self._execute("DELETE", bucket_name, query_params={"lifecycle": ""})

    def get_bucket_lifecycle(self, bucket_name):
        """
        Get bucket lifecycle configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: :class:`LifecycleConfig <LifecycleConfig>` object.

        Example::
            config = minio.get_bucket_lifecycle("my-bucketname")
        """
        check_bucket_name(bucket_name)
        try:
            response = self._execute(
                "GET", bucket_name, query_params={"lifecycle": ""},
            )
            return unmarshal(LifecycleConfig, response.data.decode())
        except S3Error as exc:
            if exc.code != "NoSuchLifecycleConfiguration":
                raise
        return None

    def set_bucket_lifecycle(self, bucket_name, config):
        """
        Set bucket lifecycle configuration to a bucket.

        :param bucket_name: Name of the bucket.
        :param config: :class:`LifecycleConfig <LifecycleConfig>` object.

        Example::
            config = LifecycleConfig(
                [
                    Rule(
                        ENABLED,
                        rule_filter=Filter(prefix="logs/"),
                        rule_id="rule2",
                        expiration=Expiration(days=365),
                    ),
                ],
            )
            minio.set_bucket_lifecycle("my-bucketname", config)
        """
        check_bucket_name(bucket_name)
        if not isinstance(config, LifecycleConfig):
            raise ValueError("config must be LifecycleConfig type")
        body = marshal(config)
        self._execute(
            "PUT",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"lifecycle": ""},
        )

    def delete_bucket_tags(self, bucket_name):
        """
        Delete tags configuration of a bucket.

        :param bucket_name: Name of the bucket.

        Example::
            minio.delete_bucket_tags("my-bucketname")
        """
        check_bucket_name(bucket_name)
        self._execute("DELETE", bucket_name, query_params={"tagging": ""})

    def get_bucket_tags(self, bucket_name):
        """
        Get tags configuration of a bucket.

        :param bucket_name: Name of the bucket.
        :return: :class:`Tags <Tags>` object.

        Example::
            tags = minio.get_bucket_tags("my-bucketname")
        """
        check_bucket_name(bucket_name)
        try:
            response = self._execute(
                "GET", bucket_name, query_params={"tagging": ""},
            )
            tagging = unmarshal(Tagging, response.data.decode())
            return tagging.tags()
        except S3Error as exc:
            if exc.code != "NoSuchTagSet":
                raise
        return None

    def set_bucket_tags(self, bucket_name, tags):
        """
        Set tags configuration to a bucket.

        :param bucket_name: Name of the bucket.
        :param tags: :class:`Tags <Tags>` object.

        Example::
            tags = Tags.new_bucket_tags()
            tags["Project"] = "Project One"
            tags["User"] = "jsmith"
            minio.set_bucket_tags("my-bucketname", tags)
        """
        check_bucket_name(bucket_name)
        if not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        body = marshal(Tagging(tags))
        self._execute(
            "PUT",
            bucket_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params={"tagging": ""},
        )

    def delete_object_tags(self, bucket_name, object_name, version_id=None):
        """
        Delete tags configuration of an object.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param version_id: Version ID of the Object.

        Example::
            minio.delete_object_tags("my-bucketname", "my-objectname")
        """
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        query_params = {"versionId": version_id} if version_id else {}
        query_params["tagging"] = ""
        self._execute(
            "DELETE",
            bucket_name,
            object_name=object_name,
            query_params=query_params,
        )

    def get_object_tags(self, bucket_name, object_name, version_id=None):
        """
        Get tags configuration of a object.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param version_id: Version ID of the Object.
        :return: :class:`Tags <Tags>` object.

        Example::
            tags = minio.get_object_tags("my-bucketname", "my-objectname")
        """
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        query_params = {"versionId": version_id} if version_id else {}
        query_params["tagging"] = ""
        try:
            response = self._execute(
                "GET",
                bucket_name,
                object_name=object_name,
                query_params=query_params,
            )
            tagging = unmarshal(Tagging, response.data.decode())
            return tagging.tags()
        except S3Error as exc:
            if exc.code != "NoSuchTagSet":
                raise
        return None

    def set_object_tags(self, bucket_name, object_name, tags, version_id=None):
        """
        Set tags configuration to an object.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param version_id: Version ID of the Object.
        :param tags: :class:`Tags <Tags>` object.

        Example::
            tags = Tags.new_object_tags()
            tags["Project"] = "Project One"
            tags["User"] = "jsmith"
            minio.set_object_tags("my-bucketname", "my-objectname", tags)
        """
        check_bucket_name(bucket_name)
        check_non_empty_string(object_name)
        if not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        body = marshal(Tagging(tags))
        query_params = {"versionId": version_id} if version_id else {}
        query_params["tagging"] = ""
        self._execute(
            "PUT",
            bucket_name,
            object_name=object_name,
            body=body,
            headers={"Content-MD5": md5sum_hash(body)},
            query_params=query_params,
        )

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
            use_api_v1=False,
            include_version=False,
    ):
        """
        List objects optionally including versions.
        Note: Its required to send empty values to delimiter/prefix and 1000 to
        max-keys when not provided for server-side bucket policy evaluation to
        succeed; otherwise AccessDenied error will be returned for such
        policies.
        """

        check_bucket_name(bucket_name)

        if version_id_marker:
            include_version = True

        is_truncated = True
        while is_truncated:
            query = {}
            if include_version:
                query["versions"] = ""
            elif not use_api_v1:
                query["list-type"] = "2"

            if not include_version and not use_api_v1:
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
                elif use_api_v1:
                    query["marker"] = start_after
                else:
                    query["start-after"] = start_after
            if version_id_marker:
                query["version-id-marker"] = version_id_marker

            response = self._execute("GET", bucket_name, query_params=query)

            if include_version:
                objects, is_truncated, start_after, version_id_marker = (
                    parse_list_object_versions(response.data, bucket_name)
                )
            elif use_api_v1:
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

    def _list_multipart_uploads(self, bucket_name, delimiter=None,
                                encoding_type=None, key_marker=None,
                                max_uploads=None, prefix=None,
                                upload_id_marker=None, extra_headers=None,
                                extra_query_params=None):
        """
        Execute ListMultipartUploads S3 API.

        :param bucket_name: Name of the bucket.
        :param region: (Optional) Region of the bucket.
        :param delimiter: (Optional) Delimiter on listing.
        :param encoding_type: (Optional) Encoding type.
        :param key_marker: (Optional) Key marker.
        :param max_uploads: (Optional) Maximum upload information to fetch.
        :param prefix: (Optional) Prefix on listing.
        :param upload_id_marker: (Optional) Upload ID marker.
        :param extra_headers: (Optional) Extra headers for advanced usage.
        :param extra_query_params: (Optional) Extra query parameters for
            advanced usage.
        :return:
            :class:`ListMultipartUploadsResult <ListMultipartUploadsResult>`
                object
        """

        query_params = extra_query_params or {}
        query_params.update(
            {
                "uploads": "",
                "delimiter": delimiter or "",
                "max-uploads": str(max_uploads or 1000),
                "prefix": prefix or "",
                "encoding-type": "url",
            },
        )
        if encoding_type:
            query_params["encoding-type"] = encoding_type
        if key_marker:
            query_params["key-marker"] = key_marker
        if upload_id_marker:
            query_params["upload-id-marker"] = upload_id_marker

        response = self._execute(
            "GET",
            bucket_name,
            query_params=query_params,
            headers=extra_headers,
        )
        return parse_list_multipart_uploads(response.data)

    def _list_parts(self, bucket_name, object_name, upload_id,
                    max_parts=None, part_number_marker=None,
                    extra_headers=None, extra_query_params=None):
        """
        Execute ListParts S3 API.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param upload_id: Upload ID.
        :param region: (Optional) Region of the bucket.
        :param max_parts: (Optional) Maximum parts information to fetch.
        :param part_number_marker: (Optional) Part number marker.
        :param extra_headers: (Optional) Extra headers for advanced usage.
        :param extra_query_params: (Optional) Extra query parameters for
            advanced usage.
        :return: :class:`ListPartsResult <ListPartsResult>` object
        """

        query_params = extra_query_params or {}
        query_params.update(
            {
                "uploadId": upload_id,
                "max-parts": str(max_parts or 1000),
            },
        )
        if part_number_marker:
            query_params["part-number-marker"] = part_number_marker

        response = self._execute(
            "GET",
            bucket_name,
            object_name=object_name,
            query_params=query_params,
            headers=extra_headers,
        )
        return parse_list_parts(response.data)
