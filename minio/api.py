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

# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches
# pylint: disable=too-many-function-args
# pylint: disable=too-many-lines
# pylint: disable=too-many-public-methods
# pylint: disable=too-many-statements
# pylint: disable=too-many-locals

"""
Simple Storage Service (aka S3) client to perform bucket and object operations.
"""

from __future__ import absolute_import, annotations

import io
import itertools
import json
import os
import tarfile
from collections.abc import Iterable
from datetime import datetime, timedelta
from io import BytesIO
from random import random
from typing import Any, BinaryIO, Iterator, Optional, TextIO, Union, cast
from urllib.parse import quote, urlencode, urlunsplit
from xml.etree import ElementTree as ET

import certifi
import urllib3
from urllib3 import Retry
from urllib3._collections import HTTPHeaderDict

try:
    from urllib3.response import BaseHTTPResponse  # type: ignore[attr-defined]
except ImportError:
    from urllib3.response import HTTPResponse as BaseHTTPResponse

from urllib3.util import Timeout

from . import time
from .checksum import (MD5, SHA256, UNSIGNED_PAYLOAD, ZERO_MD5_HASH,
                       ZERO_SHA256_HASH, Algorithm, base64_string,
                       base64_string_to_sum, hex_string, make_headers,
                       new_hashers)
from .commonconfig import (COPY, REPLACE, ComposeSource, CopySource,
                           SnowballObject, Tags)
from .credentials import StaticProvider
from .credentials.providers import Provider
from .datatypes import (Bucket, CompleteMultipartUploadResult, EventIterable,
                        ListAllMyBucketsResult, ListMultipartUploadsResult,
                        ListPartsResult, Object, Part, PostPolicy,
                        parse_copy_object, parse_list_objects)
from .deleteobjects import (DeleteError, DeleteObject, DeleteRequest,
                            DeleteResult)
from .error import InvalidResponseError, S3Error, ServerError
from .helpers import (_DEFAULT_USER_AGENT, MAX_MULTIPART_COUNT,
                      MAX_MULTIPART_OBJECT_SIZE, MAX_PART_SIZE, MIN_PART_SIZE,
                      BaseURL, HTTPQueryDict, ObjectWriteResult, ProgressType,
                      RegionMap, ThreadPool, check_bucket_name,
                      check_object_name, check_sse, check_ssec, get_part_info,
                      headers_to_strings, is_valid_policy_type, makedirs,
                      normalize_headers, queryencode, read_part_data)
from .legalhold import LegalHold
from .lifecycleconfig import LifecycleConfig
from .notificationconfig import NotificationConfig
from .objectlockconfig import ObjectLockConfig
from .replicationconfig import ReplicationConfig
from .retention import Retention
from .select import SelectObjectReader, SelectRequest
from .signer import presign_v4, sign_v4_s3
from .sse import Sse, SseCustomerKey
from .sseconfig import SSEConfig
from .tagging import Tagging
from .time import to_http_header, to_iso8601utc
from .versioningconfig import VersioningConfig
from .xml import Element, SubElement, findtext, getbytes, marshal, unmarshal


class Minio:
    """
    Simple Storage Service (aka S3) client to perform bucket and object
    operations.
    """
    _region_map: RegionMap
    _base_url: BaseURL
    _user_agent: str
    _trace_stream: Optional[TextIO]
    _provider: Optional[Provider]
    _http: urllib3.PoolManager

    def __init__(
            self,
            endpoint: str,
            access_key: Optional[str] = None,
            secret_key: Optional[str] = None,
            session_token: Optional[str] = None,
            secure: bool = True,
            region: Optional[str] = None,
            http_client: Optional[urllib3.PoolManager] = None,
            credentials: Optional[Provider] = None,
            cert_check: bool = True,
    ):
        """
        Initializes a new Minio client object.

        Args:
            endpoint (str):
                Hostname of an S3 service.

            access_key (Optional[str], default=None):
                Access key (aka user ID) of your account in the S3 service.

            secret_key (Optional[str], default=None):
                Secret key (aka password) of your account in the S3 service.

            session_token (Optional[str], default=None):
                Session token of your account in the S3 service.

            secure (bool, default=True):
                Flag to indicate whether to use a secure (TLS) connection
                to the S3 service.

            region (Optional[str], default=None):
                Region name of buckets in the S3 service.

            http_client (Optional[urllib3.PoolManager], default=None):
                Customized HTTP client.

            credentials (Optional[Provider], default=None):
                Credentials provider of your account in the S3 service.

            cert_check (bool, default=True):
                Flag to enable/disable server certificate validation
                for HTTPS connections.

        Notes:
            The `Minio` object is thread-safe when used with the Python
            `threading` library. However, it is **not** safe to share it
            between multiple processes, for example when using
            `multiprocessing.Pool`. To avoid issues, create a new `Minio`
            object in each process instead of sharing it.

        Example:
            >>> from minio import Minio
            >>>
            >>> # Create client with anonymous access
            >>> client = Minio(endpoint="play.min.io")
            >>>
            >>> # Create client with access and secret key
            >>> client = Minio(
            ...     endpoint="s3.amazonaws.com",
            ...     access_key="ACCESS-KEY",
            ...     secret_key="SECRET-KEY",
            ... )
            >>>
            >>> # Create client with specific region
            >>> client = Minio(
            ...     endpoint="play.minio.io:9000",
            ...     access_key="Q3AM3UQ867SPQQA43P2F",
            ...     secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
            ...     region="my-region",
            ... )
            >>>
            >>> # Create client with custom HTTP client using proxy
            >>> import urllib3
            >>> client = Minio(
            ...     endpoint="SERVER:PORT",
            ...     access_key="ACCESS_KEY",
            ...     secret_key="SECRET_KEY",
            ...     secure=True,
            ...     http_client=urllib3.ProxyManager(
            ...         "https://PROXYSERVER:PROXYPORT/",
            ...         timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
            ...         cert_reqs="CERT_REQUIRED",
            ...         retries=urllib3.Retry(
            ...             total=5,
            ...             backoff_factor=0.2,
            ...             status_forcelist=[500, 502, 503, 504],
            ...         ),
            ...     ),
            ... )
        """
        # Validate http client has correct base class.
        if http_client and not isinstance(http_client, urllib3.PoolManager):
            raise TypeError(
                "HTTP client should be urllib3.PoolManager like object, "
                f"got {type(http_client).__name__}",
            )

        self._region_map = RegionMap()
        self._base_url = BaseURL(
            ("https://" if secure else "http://") + endpoint,
            region,
        )
        self._user_agent = _DEFAULT_USER_AGENT
        self._trace_stream = None
        if access_key:
            if secret_key is None:
                raise ValueError("secret key must be provided with access key")
            credentials = StaticProvider(access_key, secret_key, session_token)
        self._provider = credentials

        # Load CA certificates from SSL_CERT_FILE file if set
        timeout = timedelta(minutes=5).seconds
        self._http = http_client or urllib3.PoolManager(
            timeout=Timeout(connect=timeout, read=timeout),
            maxsize=10,
            cert_reqs='CERT_REQUIRED' if cert_check else 'CERT_NONE',
            ca_certs=os.environ.get('SSL_CERT_FILE') or certifi.where(),
            retries=Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def __del__(self):
        if hasattr(self, "_http"):  # Only required for unit test run
            self._http.clear()

    @staticmethod
    def _gen_read_headers(
            ssec: Optional[SseCustomerKey] = None,
            offset: int = 0,
            length: Optional[int] = None,
            match_etag: Optional[str] = None,
            not_match_etag: Optional[str] = None,
            modified_since: Optional[datetime] = None,
            unmodified_since: Optional[datetime] = None,
            fetch_checksum: bool = False,
    ) -> HTTPHeaderDict:
        """Generates conditional headers for get/head object."""
        headers = HTTPHeaderDict()
        if ssec:
            headers.extend(ssec.headers())
        if offset or length:
            end = (offset + length - 1) if length else ""
            headers['Range'] = f"bytes={offset}-{end}"
        if match_etag:
            headers["if-match"] = match_etag
        if not_match_etag:
            headers["if-none-match"] = not_match_etag
        if modified_since:
            headers["if-modified-since"] = to_http_header(modified_since)
        if unmodified_since:
            headers["if-unmodified-since"] = to_http_header(unmodified_since)
        if fetch_checksum:
            headers["x-amz-checksum-mode"] = "ENABLED"
        return headers

    @staticmethod
    def _gen_write_headers(
            headers: Optional[HTTPHeaderDict] = None,
            user_metadata: Optional[HTTPHeaderDict] = None,
            sse: Optional[Sse] = None,
            tags: Optional[Tags] = None,
            retention: Optional[Retention] = None,
            legal_hold: bool = False,
    ) -> HTTPHeaderDict:
        """Generate headers for given parameters."""
        headers = headers.copy() if headers else HTTPHeaderDict()
        if user_metadata:
            headers.extend(user_metadata)
        headers = normalize_headers(headers)
        if sse:
            headers.extend(sse.headers())
        if tags:
            headers["x-amz-tagging"] = urlencode(
                list(tags.items()), quote_via=quote,
            )
        if retention and retention.mode:
            headers["x-amz-object-lock-mode"] = retention.mode
            headers["x-amz-object-lock-retain-until-date"] = cast(
                str, to_iso8601utc(retention.retain_until_date),
            )
        if legal_hold:
            headers["x-amz-object-lock-legal-hold"] = "ON"
        return headers

    def _handle_redirect_response(
            self,
            method: str,
            response: BaseHTTPResponse,
            bucket_name: Optional[str] = None,
            retry: bool = False,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Handle redirect response indicates whether retry HEAD request
        on failure.
        """
        code, message = {
            301: ("PermanentRedirect", "Moved Permanently"),
            307: ("Redirect", "Temporary redirect"),
            400: ("BadRequest", "Bad request"),
        }.get(response.status, (None, None))
        region = response.headers.get("x-amz-bucket-region")
        if message and region:
            message += "; use region " + region

        if (
                retry and region and method == "HEAD" and bucket_name and
                self._region_map.get(bucket_name)
        ):
            code, message = ("RetryHead", None)

        return code, message

    def _url_open(
            self,
            method: str,
            region: str,
            bucket_name: Optional[str] = None,
            object_name: Optional[str] = None,
            body: Optional[bytes] = None,
            headers: Optional[HTTPHeaderDict] = None,
            query_params: Optional[HTTPQueryDict] = None,
            preload_content: bool = True,
            no_body_trace: bool = False,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> BaseHTTPResponse:
        """Execute HTTP request."""
        url = self._base_url.build(
            method=method,
            region=region,
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
            extra_query_params=extra_query_params,
        )

        headers = headers.copy() if headers else HTTPHeaderDict()
        if extra_headers:
            headers.extend(extra_headers)

        headers["Host"] = url.netloc
        headers["User-Agent"] = self._user_agent
        content_sha256 = headers.get("x-amz-content-sha256")
        content_md5 = headers.get("Content-MD5")
        if method in ["PUT", "POST"]:
            headers["Content-Length"] = str(len(body or b""))
            if not headers.get("Content-Type"):
                headers["Content-Type"] = "application/octet-stream"
        if body is None:
            content_sha256 = content_sha256 or ZERO_SHA256_HASH
            content_md5 = content_md5 or ZERO_MD5_HASH
        else:
            if not content_sha256:
                if self._base_url.is_https:
                    content_sha256 = UNSIGNED_PAYLOAD
                else:
                    sha256_checksum = headers.get("x-amz-checksum-sha256")
                    content_sha256 = hex_string(
                        base64_string_to_sum(sha256_checksum) if sha256_checksum
                        else SHA256.hash(body),
                    )
            if not content_md5 and content_sha256 == UNSIGNED_PAYLOAD:
                content_md5 = base64_string(MD5.hash(body))
        if not headers.get("x-amz-content-sha256"):
            headers["x-amz-content-sha256"] = cast(str, content_sha256)
        if not headers.get("Content-MD5") and content_md5:
            headers["Content-MD5"] = content_md5
        date = time.utcnow()
        headers["x-amz-date"] = time.to_amz_date(date)

        if self._provider is not None:
            creds = self._provider.retrieve()
            if creds.session_token:
                headers["X-Amz-Security-Token"] = creds.session_token
            headers = sign_v4_s3(
                method=method,
                url=url,
                region=region,
                headers=headers,
                credentials=creds,
                content_sha256=cast(str, content_sha256),
                date=date,
            )

        if self._trace_stream:
            self._trace_stream.write("---------START-HTTP---------\n")
            query = ("?" + url.query) if url.query else ""
            self._trace_stream.write(f"{method} {url.path}{query} HTTP/1.1\n")
            self._trace_stream.write(
                headers_to_strings(headers, titled_key=True),
            )
            self._trace_stream.write("\n")
            if not no_body_trace and body is not None:
                self._trace_stream.write("\n")
                self._trace_stream.write(
                    body.decode() if isinstance(body, bytes) else str(body),
                )
                self._trace_stream.write("\n")
            self._trace_stream.write("\n")

        response = self._http.urlopen(
            method,
            urlunsplit(url),
            body=body,
            headers=headers,
            preload_content=preload_content,
        )

        if self._trace_stream:
            self._trace_stream.write(f"HTTP/1.1 {response.status}\n")
            self._trace_stream.write(
                headers_to_strings(response.headers),
            )
            self._trace_stream.write("\n")

        if response.status in [200, 204, 206]:
            if self._trace_stream:
                if preload_content:
                    self._trace_stream.write("\n")
                    self._trace_stream.write(response.data.decode())
                    self._trace_stream.write("\n")
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
                "application/xml" not in response.headers.get(
                    "content-type", "",
                ).split(";")
        ):
            if self._trace_stream:
                self._trace_stream.write("----------END-HTTP----------\n")
            if response.status == 304 and not response.data:
                raise ServerError(
                    f"server failed with HTTP status code {response.status}",
                    response.status,
                )
            raise InvalidResponseError(
                response.status,
                cast(str, response.headers.get("content-type")),
                response.data.decode() if response.data else None,
            )

        if not response.data and method != "HEAD":
            if self._trace_stream:
                self._trace_stream.write("----------END-HTTP----------\n")
            raise InvalidResponseError(
                response.status,
                response.headers.get("content-type"),
                None,
            )

        response_error = S3Error.fromxml(response) if response.data else None

        if self._trace_stream:
            self._trace_stream.write("----------END-HTTP----------\n")

        error_map = {
            301: lambda: self._handle_redirect_response(
                method, response, bucket_name, True,
            ),
            307: lambda: self._handle_redirect_response(
                method, response, bucket_name, True,
            ),
            400: lambda: self._handle_redirect_response(
                method, response, bucket_name, True,
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
                    f"server failed with HTTP status code {response.status}",
                    response.status,
                )
            response_error = S3Error(
                response=response,
                code=cast(str, code),
                message=cast(Union[str, None], message),
                resource=url.path,
                request_id=response.headers.get("x-amz-request-id"),
                host_id=response.headers.get("x-amz-id-2"),
                bucket_name=bucket_name,
                object_name=object_name,
            )

        if response_error.code in ["NoSuchBucket", "RetryHead"]:
            if bucket_name is not None:
                self._region_map.remove(bucket_name)

        raise response_error

    def _execute(
            self,
            method: str,
            bucket_name: Optional[str] = None,
            object_name: Optional[str] = None,
            body: Optional[bytes] = None,
            headers: Optional[HTTPHeaderDict] = None,
            query_params: Optional[HTTPQueryDict] = None,
            preload_content: bool = True,
            no_body_trace: bool = False,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> BaseHTTPResponse:
        """Execute HTTP request."""
        region = self._get_region(
            bucket_name=bucket_name,
            region=region,
        )

        try:
            return self._url_open(
                method=method,
                region=region,
                bucket_name=bucket_name,
                object_name=object_name,
                body=body,
                headers=headers,
                query_params=query_params,
                preload_content=preload_content,
                no_body_trace=no_body_trace,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
        except S3Error as exc:
            if exc.code != "RetryHead":
                raise

        # Retry only once on RetryHead error.
        try:
            return self._url_open(
                method=method,
                region=region,
                bucket_name=bucket_name,
                object_name=object_name,
                body=body,
                headers=headers,
                query_params=query_params,
                preload_content=preload_content,
                no_body_trace=no_body_trace,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
        except S3Error as exc:
            if exc.code != "RetryHead":
                raise

            code, message = self._handle_redirect_response(
                method, exc.response, bucket_name,
            )
            raise exc.copy(cast(str, code), cast(str, message))

    def _get_region(
            self,
            bucket_name: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> str:
        """
        Return region of given bucket either from region cache or set in
        constructor.
        """

        if (
                region is not None and self._base_url.region is not None and
                region != self._base_url.region
        ):
            raise ValueError(
                f"region must be {self._base_url.region}, but passed {region}",
            )

        if region is not None:
            return region

        if self._base_url.region is not None:
            return self._base_url.region

        if not bucket_name or not self._provider:
            return "us-east-1"

        region = self._region_map.get(bucket_name)
        if region:
            return region

        # Execute GetBucketLocation REST API to get region of the bucket.
        response = self._url_open(
            method="GET",
            region="us-east-1",
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"location": ""}),
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

        element = ET.fromstring(response.data.decode())
        if not element.text:
            region = "us-east-1"
        elif element.text == "EU" and self._base_url.is_aws_host:
            region = "eu-west-1"
        else:
            region = element.text

        self._region_map.set(bucket_name, region)
        return region

    def set_app_info(self, app_name: str, app_version: str):
        """
        Set your application name and version to user agent header.

        Args:
            app_name (str):
                Application name.

            app_version (str):
                Application version.

        Example:
            >>> client.set_app_info("my_app", "1.0.2")
        """
        if not (app_name and app_version):
            raise ValueError("Application name/version cannot be empty.")
        self._user_agent = f"{_DEFAULT_USER_AGENT} {app_name}/{app_version}"

    def trace_on(self, stream: TextIO):
        """
        Enable http trace.

        Args:
            stream (TextIO):
                Stream for writing HTTP call tracing.

        Example:
            >>> client.trace_on(sys.stdout)
        """
        if not stream:
            raise ValueError('Input stream for trace output is invalid.')
        # Save new output stream.
        self._trace_stream = stream

    def trace_off(self):
        """Disable HTTP trace."""
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

    def select_object_content(
            self,
            bucket_name: str,
            object_name: str,
            request: SelectRequest,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> SelectObjectReader:
        """
        Select content of an object by SQL expression.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            request (SelectRequest):
                Select request.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            SelectObjectReader:
                A reader object representing the results of the select
                operation.

        Example:
            >>> with client.select_object_content(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object.csv",
            ...     request=SelectRequest(
            ...         expression="select * from S3Object",
            ...         input_serialization=CSVInputSerialization(),
            ...         output_serialization=CSVOutputSerialization(),
            ...         request_progress=True,
            ...     ),
            ... ) as result:
            ...     for data in result.stream():
            ...         print(data.decode())
            ...     print(result.stats())
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        if not isinstance(request, SelectRequest):
            raise ValueError("request must be SelectRequest type")
        body = marshal(request)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        response = self._execute(
            method="POST",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"select": "", "select-type": "2"}),
            preload_content=False,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return SelectObjectReader(response)

    def make_bucket(
            self,
            bucket_name: str,
            location: Optional[str] = None,
            object_lock: bool = False,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Create a bucket with region and optional object lock.

        Args:
            bucket_name (str):
                Name of the bucket.

            location (Optional[str], default=None):
                Region in which the bucket is to be created.

            object_lock (bool, default=False):
                Flag to enable the object-lock feature.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> # Create bucket
            >>> client.make_bucket(bucket_name="my-bucket")
            >>>
            >>> # Create bucket in a specific region
            >>> client.make_bucket(
            ...     bucket_name="my-bucket",
            ...     location="eu-west-1",
            ... )
            >>>
            >>> # Create bucket with object-lock in a region
            >>> client.make_bucket(
            ...     bucket_name="my-bucket",
            ...     location="eu-west-2",
            ...     object_lock=True,
            ... )
        """
        check_bucket_name(bucket_name, True,
                          s3_check=self._base_url.is_aws_host)
        if self._base_url.region:
            # Error out if region does not match with region passed via
            # constructor.
            if location and self._base_url.region != location:
                raise ValueError(
                    f"region must be {self._base_url.region}, "
                    f"but passed {location}"
                )
        location = self._base_url.region or location or "us-east-1"
        headers = HTTPHeaderDict()
        if object_lock:
            headers["x-amz-bucket-object-lock-enabled"] = "true"
        body = None
        if location != "us-east-1":
            element = Element("CreateBucketConfiguration")
            SubElement(element, "LocationConstraint", location)
            body = getbytes(element)
        self._url_open(
            method="PUT",
            region=location,
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        self._region_map.set(bucket_name, location)

    def _list_buckets(
            self,
            bucket_region: Optional[str] = None,
            max_buckets: int = 10000,
            prefix: Optional[str] = None,
            continuation_token: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ListAllMyBucketsResult:
        """Do ListBuckets S3 API."""
        query_params = HTTPQueryDict()
        query_params["max-buckets"] = str(
            max_buckets if max_buckets > 0 else 10000,
        )
        if bucket_region is not None:
            query_params["bucket-region"] = bucket_region
        if prefix:
            query_params["prefix"] = prefix
        if continuation_token:
            query_params["continuation-token"] = continuation_token

        response = self._execute(
            method="GET",
            query_params=query_params,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return unmarshal(ListAllMyBucketsResult, response.data.decode())

    def list_buckets(
            self,
            bucket_region: Optional[str] = None,
            max_buckets: int = 10000,
            prefix: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Iterator[Bucket]:
        """
        List information of all accessible buckets.

        Args:
            bucket_region (Optional[str], default=None):
                Fetch buckets from the specified region.

            max_buckets (int, default=10000):
                Maximum number of buckets to fetch.

            prefix (Optional[str], default=None):
                Return only buckets whose names start with this prefix.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Iterator[Bucket]:
                An iterator of :class:`minio.datatypes.Bucket` objects.

        Example:
            >>> buckets = client.list_buckets()
            >>> for bucket in buckets:
            ...     print(bucket.name, bucket.creation_date)
        """
        continuation_token: Optional[str] = ""
        while continuation_token is not None:
            result = self._list_buckets(
                bucket_region=bucket_region,
                max_buckets=max_buckets,
                prefix=prefix,
                continuation_token=continuation_token,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            continuation_token = result.continuation_token
            yield from result.buckets

    def bucket_exists(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> bool:
        """
        Check if a bucket exists.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            bool:
                True if the bucket exists, False otherwise.

        Example:
            >>> if client.bucket_exists(bucket_name="my-bucket"):
            ...     print("my-bucket exists")
            ... else:
            ...     print("my-bucket does not exist")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        try:
            self._execute(
                method="HEAD",
                bucket_name=bucket_name,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            return True
        except S3Error as exc:
            if exc.code != "NoSuchBucket":
                raise
        return False

    def remove_bucket(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Remove an empty bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.remove_bucket(bucket_name="my-bucket")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        self._execute(
            method="DELETE",
            bucket_name=bucket_name,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        self._region_map.remove(bucket_name)

    def get_bucket_policy(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> str:
        """
        Get the bucket policy configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            str:
                Bucket policy configuration as a JSON string.

        Example:
            >>> policy = client.get_bucket_policy(bucket_name="my-bucket")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        response = self._execute(
            method="GET",
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"policy": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return response.data.decode()

    def _execute_delete_bucket(
            self,
            bucket_name: str,
            query_params: HTTPQueryDict,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """ Delete any bucket API. """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        self._execute(
            method="DELETE",
            bucket_name=bucket_name,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def delete_bucket_policy(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the bucket policy configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_bucket_policy(bucket_name="my-bucket")
        """
        self._execute_delete_bucket(
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"policy": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def set_bucket_policy(
            self,
            bucket_name: str,
            policy: str | bytes,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the bucket policy configuration for a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            policy (str | bytes):
                Bucket policy configuration as a JSON string.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> # Example anonymous read-only bucket policy
            >>> policy = {
            ...     "Version": "2012-10-17",
            ...     "Statement": [
            ...         {
            ...             "Effect": "Allow",
            ...             "Principal": {"AWS": "*"},
            ...             "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
            ...             "Resource": "arn:aws:s3:::my-bucket",
            ...         },
            ...         {
            ...             "Effect": "Allow",
            ...             "Principal": {"AWS": "*"},
            ...             "Action": "s3:GetObject",
            ...             "Resource": "arn:aws:s3:::my-bucket/*",
            ...         },
            ...     ],
            ... }
            >>> client.set_bucket_policy(
            ...     bucket_name="my-bucket",
            ...     policy=json.dumps(policy),
            ... )
            >>> # Example anonymous read-write bucket policy
            >>> policy = {
            ...     "Version": "2012-10-17",
            ...     "Statement": [
            ...         {
            ...             "Effect": "Allow",
            ...             "Principal": {"AWS": "*"},
            ...             "Action": [
            ...                 "s3:GetBucketLocation",
            ...                 "s3:ListBucket",
            ...                 "s3:ListBucketMultipartUploads",
            ...             ],
            ...             "Resource": "arn:aws:s3:::my-bucket",
            ...         },
            ...         {
            ...             "Effect": "Allow",
            ...             "Principal": {"AWS": "*"},
            ...             "Action": [
            ...                 "s3:GetObject",
            ...                 "s3:PutObject",
            ...                 "s3:DeleteObject",
            ...                 "s3:ListMultipartUploadParts",
            ...                 "s3:AbortMultipartUpload",
            ...             ],
            ...             "Resource": "arn:aws:s3:::my-bucket/images/*",
            ...         },
            ...     ],
            ... }
            >>> client.set_bucket_policy(
            ...     bucket_name="my-bucket",
            ...     policy=json.dumps(policy),
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        is_valid_policy_type(policy)
        body = policy if isinstance(policy, bytes) else policy.encode()
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"policy": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_bucket_notification(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> NotificationConfig:
        """
        Get the notification configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            NotificationConfig:
                The notification configuration of the bucket.

        Example:
            >>> config = client.get_bucket_notification(bucket_name="my-bucket")
    """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        response = self._execute(
            method="GET",
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"notification": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return unmarshal(NotificationConfig, response.data.decode())

    def set_bucket_notification(
            self,
            bucket_name: str,
            config: NotificationConfig,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the notification configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            config (NotificationConfig):
                Notification configuration.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> config = NotificationConfig(
            ...     queue_config_list=[
            ...         QueueConfig(
            ...             queue="QUEUE-ARN-OF-THIS-BUCKET",
            ...             events=["s3:ObjectCreated:*"],
            ...             config_id="1",
            ...             prefix_filter_rule=PrefixFilterRule("abc"),
            ...         ),
            ...     ],
            ... )
            >>> client.set_bucket_notification(
            ...     bucket_name="my-bucket",
            ...     config=config,
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(config, NotificationConfig):
            raise ValueError("config must be NotificationConfig type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"notification": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def delete_bucket_notification(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the notification configuration of a bucket.

        On success, the S3 service stops sending event notifications
        that were previously configured for the bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_bucket_notification(bucket_name="my-bucket")
        """
        self.set_bucket_notification(
            bucket_name=bucket_name,
            config=NotificationConfig(),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def set_bucket_encryption(
            self,
            bucket_name: str,
            config: SSEConfig,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the encryption configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            config (SSEConfig):
                Server-side encryption configuration.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.set_bucket_encryption(
            ...     bucket_name="my-bucket",
            ...     config=SSEConfig(Rule.new_sse_s3_rule()),
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(config, SSEConfig):
            raise ValueError("config must be SSEConfig type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"encryption": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_bucket_encryption(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Optional[SSEConfig]:
        """
        Get the encryption configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Optional[SSEConfig]:
                The server-side encryption configuration of the bucket, or
                None if no encryption configuration is set.

        Example:
            >>> config = client.get_bucket_encryption(bucket_name="my-bucket")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                query_params=HTTPQueryDict({"encryption": ""}),
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            return unmarshal(SSEConfig, response.data.decode())
        except S3Error as exc:
            if exc.code != "ServerSideEncryptionConfigurationNotFoundError":
                raise
        return None

    def delete_bucket_encryption(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the encryption configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_bucket_encryption(bucket_name="my-bucket")
        """
        try:
            self._execute_delete_bucket(
                bucket_name=bucket_name,
                query_params=HTTPQueryDict({"encryption": ""}),
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
        except S3Error as exc:
            if exc.code != "ServerSideEncryptionConfigurationNotFoundError":
                raise

    def listen_bucket_notification(
            self,
            bucket_name: str,
            prefix: str = "",
            suffix: str = "",
            events: tuple[str, ...] = (
                's3:ObjectCreated:*',
                's3:ObjectRemoved:*',
                's3:ObjectAccessed:*',
            ),
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> EventIterable:
        """
        Listen for events on objects in a bucket matching prefix and/or suffix.

        The caller should iterate over the returned iterator to read new events
        as they occur.

        Args:
            bucket_name (str):
                Name of the bucket.

            prefix (str, default=""):
                Listen for events on objects whose names start with this prefix.

            suffix (str, default=""):
                Listen for events on objects whose names end with this suffix.

            events (tuple[str, ...], default=("s3:ObjectCreated:*",
            "s3:ObjectRemoved:*", "s3:ObjectAccessed:*")):
                Events to listen for.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            EventIterable:
                An iterator of :class:`minio.datatypes.EventIterable` containing
                event records.

        Example:
            >>> with client.listen_bucket_notification(
            ...     bucket_name="my-bucket",
            ...     prefix="my-prefix/",
            ...     events=["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
            ... ) as events:
            ...     for event in events:
            ...         print(event)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if self._base_url.is_aws_host:
            raise ValueError(
                "ListenBucketNotification API is not supported in Amazon S3",
            )

        query_params = HTTPQueryDict({
            "prefix": prefix or "",
            "suffix": suffix or "",
            "events": events,
        })
        return EventIterable(
            lambda: self._execute(
                method="GET",
                bucket_name=bucket_name,
                query_params=query_params,
                preload_content=False,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            ),
        )

    def set_bucket_versioning(
            self,
            bucket_name: str,
            config: VersioningConfig,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the versioning configuration for a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            config (VersioningConfig):
                Versioning configuration.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.set_bucket_versioning(
            ...     bucket_name="my-bucket",
            ...     config=VersioningConfig(ENABLED),
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(config, VersioningConfig):
            raise ValueError("config must be VersioningConfig type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"versioning": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_bucket_versioning(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> VersioningConfig:
        """
        Get the versioning configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            VersioningConfig:
                The versioning configuration of the bucket.

        Example:
            >>> config = client.get_bucket_versioning(bucket_name="my-bucket")
            >>> print(config.status)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        response = self._execute(
            method="GET",
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"versioning": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return unmarshal(VersioningConfig, response.data.decode())

    def fput_object(
            self,
            bucket_name: str,
            object_name: str,
            file_path: str,
            content_type: str = "application/octet-stream",
            metadata: Optional[HTTPHeaderDict] = None,
            sse: Optional[Sse] = None,
            progress: Optional[ProgressType] = None,
            part_size: int = 0,
            num_parallel_uploads: int = 3,
            tags: Optional[Tags] = None,
            retention: Optional[Retention] = None,
            legal_hold: bool = False,
            *,
            headers: Optional[HTTPHeaderDict] = None,
            user_metadata: Optional[HTTPHeaderDict] = None,
            checksum: Optional[Algorithm] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """
        Upload data from a file to an object in a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            file_path (str):
                Path to the file to upload.

            content_type (str, default="application/octet-stream"):
                Content type of the object.

            headers (Optional[HTTPHeaderDict], default=None):
                Additional headers.

            user_metadata (Optional[HTTPHeaderDict], default=None):
                User metadata of the object.

            sse (Optional[Sse], default=None):
                Server-side encryption configuration.

            progress (Optional[ProgressType], default=None):
                Progress object to track upload progress.

            part_size (int, default=0):
                Multipart upload part size in bytes.

            checksum (Optional[Algorithm], default=None):
                Algorithm for checksum computation.

            num_parallel_uploads (int, default=3):
                Number of parallel uploads.

            tags (Optional[Tags], default=None):
                Tags for the object.

            retention (Optional[Retention], default=None):
                Retention configuration.

            legal_hold (bool, default=False):
                Flag to set legal hold for the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectWriteResult:
                The result of the object upload operation.

        Example:
            >>> # Upload data
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ... )
            >>> print(
            ...     f"created {result.object_name} object; "
            ...     f"etag: {result.etag}, version-id: {result.version_id}",
            ... )

            >>> # Upload with part size
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     part_size=10*1024*1024,
            ... )

            >>> # Upload with content type
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     content_type="application/csv",
            ... )

            >>> # Upload with metadata
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     metadata={"My-Project": "one"},
            ... )

            >>> # Upload with customer key encryption
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     sse=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
            ... )

            >>> # Upload with KMS encryption
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     sse=SseKMS(
            ...         "KMS-KEY-ID",
            ...         {"Key1": "Value1", "Key2": "Value2"},
            ...     ),
            ... )

            >>> # Upload with S3-managed encryption
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     sse=SseS3(),
            ... )

            >>> # Upload with tags, retention and legal hold
            >>> date = datetime.utcnow().replace(
            ...     hour=0, minute=0, second=0, microsecond=0,
            ... ) + timedelta(days=30)
            >>> tags = Tags(for_object=True)
            >>> tags["User"] = "jsmith"
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     tags=tags,
            ...     retention=Retention(GOVERNANCE, date),
            ...     legal_hold=True,
            ... )

            >>> # Upload with progress bar
            >>> result = client.fput_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     progress=Progress(),
            ... )
        """
        file_size = os.stat(file_path).st_size
        if user_metadata is None:
            user_metadata = metadata
        with open(file_path, "rb") as file_data:
            return self.put_object(
                bucket_name=bucket_name,
                object_name=object_name,
                data=file_data,
                length=file_size,
                content_type=content_type,
                headers=headers,
                user_metadata=user_metadata,
                sse=sse,
                checksum=checksum,
                progress=progress,
                part_size=part_size,
                num_parallel_uploads=num_parallel_uploads,
                tags=tags,
                retention=retention,
                legal_hold=legal_hold,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )

    def fget_object(
            self,
            bucket_name: str,
            object_name: str,
            file_path: str,
            request_headers: Optional[HTTPHeaderDict] = None,
            ssec: Optional[SseCustomerKey] = None,
            version_id: Optional[str] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            tmp_file_path: Optional[str] = None,
            progress: Optional[ProgressType] = None,
            *,
            match_etag: Optional[str] = None,
            not_match_etag: Optional[str] = None,
            modified_since: Optional[datetime] = None,
            unmodified_since: Optional[datetime] = None,
            fetch_checksum: bool = False,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
    ):
        """
        Download an object to a file.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            file_path (str):
                Path to the file where data will be downloaded.

            match_etag (Optional[str], default=None):
                Match ETag of the object.

            not_match_etag (Optional[str], default=None):
                None-match ETag of the object.

            modified_since (Optional[datetime], default=None):
                Condition to fetch object modified since the given date.

            unmodified_since (Optional[datetime], default=None):
                Condition to fetch object unmodified since the given date.

            fetch_checksum (bool, default=False):
                Flag to fetch object checksum.

            ssec (Optional[SseCustomerKey], default=None):
                Server-side encryption customer key.

            version_id (Optional[str], default=None):
                Version ID of the object.

            tmp_file_path (Optional[str], default=None):
                Path to a temporary file used during download.

            progress (Optional[ProgressType], default=None):
                Progress object to track download progress.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> # Download object
            >>> client.fget_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ... )
            >>>
            >>> # Download specific version of object
            >>> client.fget_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
            ... )
            >>>
            >>> # Download SSE-C encrypted object
            >>> client.fget_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     file_path="my-filename",
            ...     ssec=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)

        if os.path.isdir(file_path):
            raise ValueError(f"file {file_path} is a directory")

        # Create top level directory if needed.
        makedirs(os.path.dirname(file_path))

        stat = self.stat_object(
            bucket_name=bucket_name,
            object_name=object_name,
            ssec=ssec,
            version_id=version_id,
        )

        etag = queryencode(cast(str, stat.etag))
        # Write to a temporary file "file_path.ETAG.part.minio" before saving.
        tmp_file_path = (
            tmp_file_path or f"{file_path}.{etag}.part.minio"
        )

        response = None
        try:
            response = self.get_object(
                bucket_name=bucket_name,
                object_name=object_name,
                request_headers=request_headers,
                ssec=ssec,
                version_id=version_id,
                extra_query_params=extra_query_params,
                match_etag=match_etag,
                not_match_etag=not_match_etag,
                modified_since=modified_since,
                unmodified_since=unmodified_since,
                fetch_checksum=fetch_checksum,
                region=region,
                extra_headers=extra_headers,
            )

            if progress:
                # Set progress bar length and object name before upload
                length = int(response.headers.get('content-length', 0))
                progress.set_meta(object_name=object_name, total_length=length)

            with open(tmp_file_path, "wb") as tmp_file:
                for data in response.stream(amt=1024 * 1024):
                    size = tmp_file.write(data)
                    if progress:
                        progress.update(size)
            if os.path.exists(file_path):
                os.remove(file_path)  # For windows compatibility.
            os.rename(tmp_file_path, file_path)
            return stat
        finally:
            if response:
                response.close()
                response.release_conn()

    def get_object(
            self,
            bucket_name: str,
            object_name: str,
            offset: int = 0,
            length: Optional[int] = None,
            request_headers: Optional[HTTPHeaderDict] = None,
            ssec: Optional[SseCustomerKey] = None,
            version_id: Optional[str] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            *,
            match_etag: Optional[str] = None,
            not_match_etag: Optional[str] = None,
            modified_since: Optional[datetime] = None,
            unmodified_since: Optional[datetime] = None,
            fetch_checksum: bool = False,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
    ) -> BaseHTTPResponse:
        """
        Get object data from a bucket.

        Data is read starting at the specified offset up to the given length.
        The returned response must be closed after use to release network
        resources. To reuse the connection, explicitly call
        ``response.release_conn()``.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            ssec (Optional[SseCustomerKey], default=None):
                Server-side encryption customer key.

            offset (int, default=0):
                Start byte position of object data.

            length (Optional[int], default=None):
                Number of bytes of object data to read from offset.

            match_etag (Optional[str], default=None):
                Match ETag of the object.

            not_match_etag (Optional[str], default=None):
                None-match ETag of the object.

            modified_since (Optional[datetime], default=None):
                Condition to fetch object modified since the given date.

            unmodified_since (Optional[datetime], default=None):
                Condition to fetch object unmodified since the given date.

            fetch_checksum (bool, default=False):
                Flag to fetch object checksum.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            BaseHTTPResponse:
                An :class:`urllib3.response.BaseHTTPResponse` or
                :class:`urllib3.response.HTTPResponse` object containing
                the object data.

        Example:
            >>> # Get data of an object
            >>> try:
            ...     response = client.get_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...     )
            ...     # Read data from response
            ... finally:
            ...     response.close()
            ...     response.release_conn()
            >>>
            >>> # Get specific version of an object
            >>> try:
            ...     response = client.get_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
            ...     )
            ... finally:
            ...     response.close()
            ...     response.release_conn()
            >>>
            >>> # Get object data from offset and length
            >>> try:
            ...     response = client.get_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         offset=512,
            ...         length=1024,
            ...     )
            ... finally:
            ...     response.close()
            ...     response.release_conn()
            >>>
            >>> # Get SSE-C encrypted object
            >>> try:
            ...     response = client.get_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         ssec=SseCustomerKey(
            ...             b"32byteslongsecretkeymustprovided"
            ...         ),
            ...     )
            ... finally:
            ...     response.close()
            ...     response.release_conn()
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        check_ssec(ssec)

        headers = self._gen_read_headers(
            ssec=ssec,
            offset=offset,
            length=length,
            match_etag=match_etag,
            not_match_etag=not_match_etag,
            modified_since=modified_since,
            unmodified_since=unmodified_since,
            fetch_checksum=fetch_checksum,
        )
        if request_headers:
            request_headers = HTTPHeaderDict(request_headers)
            if request_headers.get("Range"):
                headers.pop("Range", None)
            headers.extend(request_headers)

        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id

        return self._execute(
            method="GET",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            query_params=query_params,
            preload_content=False,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def prompt_object(
            self,
            bucket_name: str,
            object_name: str,
            prompt: str,
            lambda_arn: Optional[str] = None,
            request_headers: Optional[HTTPHeaderDict] = None,
            ssec: Optional[SseCustomerKey] = None,
            version_id: Optional[str] = None,
            *,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            **kwargs: Optional[Any],
    ) -> BaseHTTPResponse:
        """
        Prompt an object using natural language.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            prompt (str):
                Natural language prompt to interact with the object using
                the AI model.

            lambda_arn (Optional[str], default=None):
                AWS Lambda ARN to use for processing the prompt.

            ssec (Optional[SseCustomerKey], default=None):
                Server-side encryption customer key.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

            **kwargs (Optional[Any]):
                Additional parameters for advanced usage.

        Returns:
            BaseHTTPResponse:
                An :class:`urllib3.response.BaseHTTPResponse` object.

        Example:
            >>> response = None
            >>> try:
            ...     response = client.prompt_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         prompt="Describe the object for me",
            ...     )
            ...     # Read data from response
            ... finally:
            ...     if response:
            ...         response.close()
            ...         response.release_conn()
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        check_ssec(ssec)

        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["lambdaArn"] = lambda_arn or ""

        if request_headers:
            extra_headers = HTTPHeaderDict(extra_headers or {})
            extra_headers.extend(request_headers)

        prompt_body = kwargs
        prompt_body["prompt"] = prompt

        body = json.dumps(prompt_body)
        return self._execute(
            method="POST",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=HTTPHeaderDict(ssec.headers()) if ssec else None,
            query_params=query_params,
            body=body.encode(),
            preload_content=False,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def copy_object(
            self,
            bucket_name: str,
            object_name: str,
            source: CopySource,
            sse: Optional[Sse] = None,
            metadata: Optional[HTTPHeaderDict] = None,
            tags: Optional[Tags] = None,
            retention: Optional[Retention] = None,
            legal_hold: bool = False,
            metadata_directive: Optional[str] = None,
            tagging_directive: Optional[str] = None,
            *,
            user_metadata: Optional[HTTPHeaderDict] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """
        Create an object by server-side copying data from another object.

        The maximum supported source object size for this API is 5 GiB.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            source (CopySource):
                Source object information.

            sse (Optional[Sse], default=None):
                Server-side encryption configuration for the destination
                object.

            user_metadata (Optional[HTTPHeaderDict], default=None):
                User-defined metadata to be applied to the destination
                object.

            tags (Optional[Tags], default=None):
                Tags for the destination object.

            retention (Optional[Retention], default=None):
                Retention configuration for the destination object.

            legal_hold (bool, default=False):
                Flag to enable legal hold on the destination object.

            metadata_directive (Optional[str], default=None):
                Directive for handling user metadata on the destination
                object.

            tagging_directive (Optional[str], default=None):
                Directive for handling tags on the destination object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectWriteResult:
                The result of the copy operation.

        Example:
            >>> from datetime import datetime, timezone
            >>> from minio.commonconfig import REPLACE, CopySource
            >>>
            >>> # Copy an object from a bucket to another
            >>> result = client.copy_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     source=CopySource(
            ...         bucket_name="my-sourcebucket",
            ...         object_name="my-sourceobject",
            ...     ),
            ... )
            >>> print(result.object_name, result.version_id)
            >>>
            >>> # Copy an object with condition
            >>> result = client.copy_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     source=CopySource(
            ...         bucket_name="my-sourcebucket",
            ...         object_name="my-sourceobject",
            ...         modified_since=datetime(
            ...             2014, 4, 1, tzinfo=timezone.utc,
            ...         ),
            ...     ),
            ... )
            >>> print(result.object_name, result.version_id)
            >>>
            >>> # Copy an object with replacing metadata
            >>> user_metadata = {"test_meta_key": "test_meta_value"}
            >>> result = client.copy_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     source=CopySource(
            ...         bucket_name="my-sourcebucket",
            ...         object_name="my-sourceobject",
            ...     ),
            ...     user_metadata=user_metadata,
            ...     metadata_directive=REPLACE,
            ... )
            >>> print(result.object_name, result.version_id)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        if not isinstance(source, CopySource):
            raise ValueError("source must be CopySource type")
        check_sse(sse)
        if tags is not None and not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        if retention is not None and not isinstance(retention, Retention):
            raise ValueError("retention must be Retention type")
        if user_metadata is None:
            user_metadata = metadata
        if user_metadata is None:
            user_metadata = metadata
        if (
                metadata_directive is not None and
                metadata_directive not in [COPY, REPLACE]
        ):
            raise ValueError(f"metadata directive must be {COPY} or {REPLACE}")
        if (
                tagging_directive is not None and
                tagging_directive not in [COPY, REPLACE]
        ):
            raise ValueError(f"tagging directive must be {COPY} or {REPLACE}")

        size = -1
        if source.offset is None and source.length is None:
            stat = self.stat_object(
                bucket_name=source.bucket_name,
                object_name=source.object_name,
                version_id=source.version_id,
                ssec=source.ssec,
            )
            size = cast(int, stat.size)

        if (
                source.offset is not None or
                source.length is not None or
                size > MAX_PART_SIZE
        ):
            if metadata_directive == COPY:
                raise ValueError(
                    "COPY metadata directive is not applicable to source "
                    "object size greater than 5 GiB",
                )
            if tagging_directive == COPY:
                raise ValueError(
                    "COPY tagging directive is not applicable to source "
                    "object size greater than 5 GiB"
                )
            return self.compose_object(
                bucket_name=bucket_name,
                object_name=object_name,
                sources=[ComposeSource.of(source)],
                sse=sse,
                user_metadata=user_metadata,
                tags=tags,
                retention=retention,
                legal_hold=legal_hold,
            )

        headers = self._gen_write_headers(
            user_metadata=user_metadata,
            sse=sse,
            tags=tags,
            retention=retention,
            legal_hold=legal_hold,
        )
        if metadata_directive:
            headers["x-amz-metadata-directive"] = metadata_directive
        if tagging_directive:
            headers["x-amz-tagging-directive"] = tagging_directive
        headers.extend(source.gen_copy_headers())
        response = self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        etag, last_modified = parse_copy_object(response)
        return ObjectWriteResult.new(
            headers=response.headers,
            bucket_name=bucket_name,
            object_name=object_name,
            etag=etag,
            last_modified=last_modified,
        )

    def _calc_part_count(self, sources: list[ComposeSource]) -> int:
        """Calculate part count."""
        object_size = 0
        part_count = 0
        i = 0
        for src in sources:
            i += 1
            stat = self.stat_object(
                bucket_name=src.bucket_name,
                object_name=src.object_name,
                version_id=src.version_id,
                ssec=src.ssec,
            )
            src.build_headers(cast(int, stat.size), cast(str, stat.etag))
            size = cast(int, stat.size)
            if src.length is not None:
                size = src.length
            elif src.offset is not None:
                size -= src.offset

            if (
                    size < MIN_PART_SIZE and
                    len(sources) != 1 and
                    i != len(sources)
            ):
                raise ValueError(
                    f"source {src.bucket_name}/{src.object_name}: size {size} "
                    f"must be greater than {MIN_PART_SIZE}"
                )

            object_size += size
            if object_size > MAX_MULTIPART_OBJECT_SIZE:
                raise ValueError(
                    f"destination object size must be less than "
                    f"{MAX_MULTIPART_OBJECT_SIZE}"
                )

            if size > MAX_PART_SIZE:
                count = int(size / MAX_PART_SIZE)
                last_part_size = size - (count * MAX_PART_SIZE)
                if last_part_size > 0:
                    count += 1
                else:
                    last_part_size = MAX_PART_SIZE
                if (
                        last_part_size < MIN_PART_SIZE and
                        len(sources) != 1 and
                        i != len(sources)
                ):
                    raise ValueError(
                        f"source {src.bucket_name}/{src.object_name}: "
                        f"for multipart split upload of {size}, "
                        f"last part size is less than {MIN_PART_SIZE}"
                    )
                part_count += count
            else:
                part_count += 1

        if part_count > MAX_MULTIPART_COUNT:
            raise ValueError(
                f"Compose sources create more than allowed multipart "
                f"count {MAX_MULTIPART_COUNT}"
            )
        return part_count

    def _upload_part_copy(
            self,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            part_number: int,
            headers: HTTPHeaderDict,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> tuple[str, Optional[datetime]]:
        """Execute UploadPartCopy S3 API."""
        query_params = HTTPQueryDict(
            {
                "partNumber": str(part_number),
                "uploadId": upload_id,
            },
        )
        response = self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return parse_copy_object(response)

    def compose_object(
            self,
            bucket_name: str,
            object_name: str,
            sources: list[ComposeSource],
            sse: Optional[Sse] = None,
            metadata: Optional[HTTPHeaderDict] = None,
            tags: Optional[Tags] = None,
            retention: Optional[Retention] = None,
            legal_hold: bool = False,
            *,
            user_metadata: Optional[HTTPHeaderDict] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """
        Create an object by combining data from multiple source objects using
        server-side copy.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            sources (list[ComposeSource]):
                List of source objects to be combined.

            sse (Optional[Sse], default=None):
                Server-side encryption configuration for the destination
                object.

            user_metadata (Optional[HTTPHeaderDict], default=None):
                User-defined metadata to be applied to the destination
                object.

            tags (Optional[Tags], default=None):
                Tags for the destination object.

            retention (Optional[Retention], default=None):
                Retention configuration for the destination object.

            legal_hold (bool, default=False):
                Flag to enable legal hold on the destination object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectWriteResult:
                The result of the compose operation.

        Example:
            >>> from minio.commonconfig import ComposeSource
            >>> from minio.sse import SseS3
            >>>
            >>> sources = [
            ...     ComposeSource(
            ...         bucket_name="my-job-bucket",
            ...         object_name="my-object-part-one",
            ...     ),
            ...     ComposeSource(
            ...         bucket_name="my-job-bucket",
            ...         object_name="my-object-part-two",
            ...     ),
            ...     ComposeSource(
            ...         bucket_name="my-job-bucket",
            ...         object_name="my-object-part-three",
            ...     ),
            ... ]
            >>>
            >>> # Create object by combining sources
            >>> result = client.compose_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     sources=sources,
            ... )
            >>> print(result.object_name, result.version_id)
            >>>
            >>> # With user metadata
            >>> result = client.compose_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     sources=sources,
            ...     user_metadata={"test_meta_key": "test_meta_value"},
            ... )
            >>> print(result.object_name, result.version_id)
            >>>
            >>> # With user metadata and SSE
            >>> result = client.compose_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     sources=sources,
            ...     sse=SseS3(),
            ... )
            >>> print(result.object_name, result.version_id)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        if not isinstance(sources, (list, tuple)) or not sources:
            raise ValueError("sources must be non-empty list or tuple type")
        i = 0
        for src in sources:
            if not isinstance(src, ComposeSource):
                raise ValueError(f"sources[{i}] must be ComposeSource type")
            i += 1
        check_sse(sse)
        if tags is not None and not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        if retention is not None and not isinstance(retention, Retention):
            raise ValueError("retention must be Retention type")

        part_count = self._calc_part_count(sources)
        if (
                part_count == 1 and
                sources[0].offset is None and
                sources[0].length is None
        ):
            return self.copy_object(
                bucket_name=bucket_name,
                object_name=object_name,
                source=CopySource.of(sources[0]),
                sse=sse,
                user_metadata=user_metadata,
                tags=tags,
                retention=retention,
                legal_hold=legal_hold,
                metadata_directive=REPLACE if user_metadata else None,
                tagging_directive=REPLACE if tags else None,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )

        headers = self._gen_write_headers(
            user_metadata=user_metadata,
            sse=sse,
            tags=tags,
            retention=retention,
            legal_hold=legal_hold,
        )
        upload_id = self._create_multipart_upload(
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
        )
        ssec_headers = (
            sse.headers() if isinstance(sse, SseCustomerKey)
            else HTTPHeaderDict()
        )
        try:
            part_number = 0
            total_parts = []
            for src in sources:
                size = cast(int, src.object_size)
                if src.length is not None:
                    size = src.length
                elif src.offset is not None:
                    size -= src.offset
                offset = src.offset or 0
                headers = cast(HTTPHeaderDict, src.headers)
                headers.extend(ssec_headers)
                if size <= MAX_PART_SIZE:
                    part_number += 1
                    if src.length is not None:
                        headers["x-amz-copy-source-range"] = (
                            f"bytes={offset}-{offset + src.length - 1}"
                        )
                    elif src.offset is not None:
                        headers["x-amz-copy-source-range"] = (
                            f"bytes={offset}-{offset + size - 1}"
                        )
                    etag, _ = self._upload_part_copy(
                        bucket_name=bucket_name,
                        object_name=object_name,
                        upload_id=upload_id,
                        part_number=part_number,
                        headers=headers,
                    )
                    total_parts.append(Part(part_number, etag))
                    continue
                while size > 0:
                    part_number += 1
                    length = size if size < MAX_PART_SIZE else MAX_PART_SIZE
                    end_bytes = offset + length - 1
                    headers_copy = headers.copy()
                    headers_copy["x-amz-copy-source-range"] = (
                        f"bytes={offset}-{end_bytes}"
                    )
                    etag, _ = self._upload_part_copy(
                        bucket_name=bucket_name,
                        object_name=object_name,
                        upload_id=upload_id,
                        part_number=part_number,
                        headers=headers_copy,
                    )
                    total_parts.append(Part(part_number, etag))
                    offset += length
                    size -= length
            result = self._complete_multipart_upload(
                bucket_name=bucket_name,
                object_name=object_name,
                upload_id=upload_id,
                parts=total_parts,
            )
            return ObjectWriteResult.new(
                headers=result.headers,
                bucket_name=cast(str, result.bucket_name),
                object_name=cast(str, result.object_name),
                version_id=result.version_id,
                etag=result.etag,
                location=result.location,
            )
        except Exception as exc:
            if upload_id:
                self._abort_multipart_upload(
                    bucket_name=bucket_name,
                    object_name=object_name,
                    upload_id=upload_id,
                )
            raise exc

    def _abort_multipart_upload(
            self,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """Execute AbortMultipartUpload S3 API."""
        self._execute(
            method="DELETE",
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=HTTPQueryDict({'uploadId': upload_id}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def _complete_multipart_upload(
            self,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            parts: list[Part],
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> CompleteMultipartUploadResult:
        """Execute CompleteMultipartUpload S3 API."""
        element = Element("CompleteMultipartUpload")
        for part in parts:
            tag = SubElement(element, "Part")
            SubElement(tag, "PartNumber", str(part.part_number))
            SubElement(tag, "ETag", '"' + part.etag + '"')
            if part.checksum_crc32:
                SubElement(tag, "ChecksumCRC32", part.checksum_crc32)
            elif part.checksum_crc32c:
                SubElement(tag, "ChecksumCRC32C", part.checksum_crc32c)
            elif part.checksum_sha1:
                SubElement(tag, "ChecksumSHA1", part.checksum_sha1)
            elif part.checksum_sha256:
                SubElement(tag, "ChecksumSHA256", part.checksum_sha256)
        body = getbytes(element)
        headers = HTTPHeaderDict(
            {
                "Content-Type": 'application/xml',
                "Content-MD5": base64_string(MD5.hash(body)),
            },
        )
        response = self._execute(
            method="POST",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({'uploadId': upload_id}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return CompleteMultipartUploadResult(response)

    def _create_multipart_upload(
            self,
            bucket_name: str,
            object_name: str,
            headers: HTTPHeaderDict,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> str:
        """Execute CreateMultipartUpload S3 API."""
        if not headers.get("Content-Type"):
            headers["Content-Type"] = "application/octet-stream"
        response = self._execute(
            method="POST",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            query_params=HTTPQueryDict({"uploads": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        element = ET.fromstring(response.data.decode())
        return cast(str, findtext(element, "UploadId", True))

    def _put_object(
            self,
            bucket_name: str,
            object_name: str,
            data: bytes,
            headers: Optional[HTTPHeaderDict] = None,
            query_params: Optional[HTTPQueryDict] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """Execute PutObject S3 API."""
        response = self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            body=data,
            headers=headers,
            query_params=query_params,
            no_body_trace=True,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return ObjectWriteResult.new(
            headers=response.headers,
            bucket_name=bucket_name,
            object_name=object_name,
        )

    def _upload_part(
            self,
            bucket_name: str,
            object_name: str,
            data: bytes,
            headers: Optional[HTTPHeaderDict],
            upload_id: str,
            part_number: int,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """Execute UploadPart S3 API."""
        query_params = HTTPQueryDict({
            "partNumber": str(part_number),
            "uploadId": upload_id,
        })
        result = self._put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=data,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return result

    def _upload_part_task(self, kwargs):
        """Upload_part task for ThreadPool."""
        return kwargs["part_number"], self._upload_part(**kwargs)

    def put_object(
            self,
            bucket_name: str,
            object_name: str,
            data: BinaryIO,
            length: int,
            content_type: str = "application/octet-stream",
            metadata: Optional[HTTPHeaderDict] = None,
            sse: Optional[Sse] = None,
            progress: Optional[ProgressType] = None,
            part_size: int = 0,
            num_parallel_uploads: int = 3,
            tags: Optional[Tags] = None,
            retention: Optional[Retention] = None,
            legal_hold: bool = False,
            write_offset: Optional[int] = None,
            *,
            headers: Optional[HTTPHeaderDict] = None,
            user_metadata: Optional[HTTPHeaderDict] = None,
            checksum: Optional[Algorithm] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """
        Upload data from a stream to an object in a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            data (BinaryIO):
                An object with a callable ``read()`` method that returns a
                bytes object.

            length (int):
                Size of the data in bytes. Use -1 for unknown size and set a
                valid ``part_size``.

            content_type (str, default="application/octet-stream"):
                Content type of the object.

            headers (Optional[HTTPHeaderDict], default=None):
                Additional headers.

            user_metadata (Optional[HTTPHeaderDict], default=None):
                User metadata for the object.

            sse (Optional[Sse], default=None):
                Server-side encryption configuration.

            progress (Optional[ProgressType], default=None):
                Progress object to track upload progress.

            part_size (int, default=0):
                Multipart upload part size in bytes.

            checksum (Optional[Algorithm], default=None):
                Algorithm for checksum computation.

            num_parallel_uploads (int, default=3):
                Number of parallel uploads.

            tags (Optional[Tags], default=None):
                Tags for the object.

            retention (Optional[Retention], default=None):
                Retention configuration.

            legal_hold (bool, default=False):
                Flag to enable legal hold on the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectWriteResult:
                The result of the object upload operation.

        Example:
            >>> # Upload simple data
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ... )
            >>> print(
            ...     f"created {result.object_name} object; "
            ...     f"etag: {result.etag}, version-id: {result.version_id}",
            ... )
            >>>
            >>> # Upload unknown-sized data with multipart
            >>> with urlopen("https://cdn.kernel.org/pub/linux/kernel/v5.x/"
            ...              "linux-5.4.81.tar.xz") as data:
            ...     result = client.put_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         data=data,
            ...         length=-1,
            ...         part_size=10*1024*1024,
            ...     )
            >>>
            >>> # Upload with content type
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     content_type="application/csv",
            ... )
            >>>
            >>> # Upload with metadata
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     metadata={"My-Project": "one"},
            ... )
            >>>
            >>> # Upload with customer key SSE
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     sse=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
            ... )
            >>>
            >>> # Upload with KMS SSE
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     sse=SseKMS(
            ...         "KMS-KEY-ID",
            ...         {"Key1": "Value1", "Key2": "Value2"},
            ...     ),
            ... )
            >>>
            >>> # Upload with S3-managed SSE
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     sse=SseS3(),
            ... )
            >>>
            >>> # Upload with tags, retention, and legal hold
            >>> date = datetime.utcnow().replace(
            ...     hour=0, minute=0, second=0, microsecond=0,
            ... ) + timedelta(days=30)
            >>> tags = Tags(for_object=True)
            >>> tags["User"] = "jsmith"
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     tags=tags,
            ...     retention=Retention(GOVERNANCE, date),
            ...     legal_hold=True,
            ... )
            >>>
            >>> # Upload with progress bar
            >>> result = client.put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"hello"),
            ...     length=5,
            ...     progress=Progress(),
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        check_sse(sse)
        if tags is not None and not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        if retention is not None and not isinstance(retention, Retention):
            raise ValueError("retention must be Retention type")
        if not callable(getattr(data, "read")):
            raise ValueError("input data must have callable read()")
        if user_metadata is None:
            user_metadata = metadata
        if write_offset is not None and write_offset < 0:
            raise ValueError("write_offset must be zero or greater")
        part_size, part_count = get_part_info(length, part_size)
        if progress:
            # Set progress bar length and object name before upload
            progress.set_meta(object_name=object_name, total_length=length)

        add_content_sha256 = self._base_url.is_https
        algorithms = [checksum or Algorithm.CRC32C]
        add_sha256_checksum = algorithms[0] == Algorithm.SHA256
        if add_content_sha256 and not add_sha256_checksum:
            algorithms.append(Algorithm.SHA256)
        hashers = new_hashers(algorithms)

        headers = self._gen_write_headers(
            headers=headers,
            user_metadata=user_metadata,
            sse=sse,
            tags=tags,
            retention=retention,
            legal_hold=legal_hold,
        )
        if write_offset is not None:
            headers["x-amz-write-offset-bytes"] = str(write_offset)
        headers["Content-Type"] = content_type or "application/octet-stream"

        object_size = length
        uploaded_size = 0
        part_number = 0
        one_byte = b""
        stop = False
        upload_id = None
        parts: list[Part] = []
        pool: Optional[ThreadPool] = None

        try:
            while not stop:
                part_number += 1
                if part_count > 0:
                    if part_number == part_count:
                        part_size = object_size - uploaded_size
                        stop = True
                    part_data = read_part_data(
                        stream=data,
                        size=part_size,
                        progress=progress,
                        hashers=hashers,
                    )
                    if len(part_data) != part_size:
                        raise IOError(
                            f"stream having not enough data;"
                            f"expected: {part_size}, "
                            f"got: {len(part_data)} bytes"
                        )
                else:
                    part_data = read_part_data(
                        stream=data,
                        size=part_size + 1,
                        part_data=one_byte,
                        progress=progress,
                        hashers=hashers,
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

                checksum_headers = make_headers(
                    hashers, add_content_sha256, add_sha256_checksum,
                )

                if part_count == 1:
                    headers.extend(checksum_headers)
                    return self._put_object(
                        bucket_name=bucket_name,
                        object_name=object_name,
                        data=part_data,
                        headers=headers,
                        region=region,
                        extra_headers=extra_headers,
                        extra_query_params=extra_query_params,
                    )

                if not upload_id:
                    headers.extend(make_headers(
                        hashers, add_content_sha256, add_sha256_checksum,
                        algorithm_only=True,
                    ))
                    upload_id = self._create_multipart_upload(
                        bucket_name=bucket_name,
                        object_name=object_name,
                        headers=headers,
                        region=region,
                        extra_headers=extra_headers,
                        extra_query_params=extra_query_params,
                    )
                    if num_parallel_uploads and num_parallel_uploads > 1:
                        pool = ThreadPool(num_parallel_uploads)
                        pool.start_parallel()

                headers = HTTPHeaderDict(
                    sse.headers() if isinstance(sse, SseCustomerKey) else None,
                )
                headers.extend(checksum_headers)
                if num_parallel_uploads > 1:
                    kwargs = {
                        "bucket_name": bucket_name,
                        "object_name": object_name,
                        "data": part_data,
                        "headers": headers,
                        "upload_id": upload_id,
                        "part_number": part_number,
                    }
                    cast(ThreadPool, pool).add_task(
                        self._upload_part_task, kwargs,
                    )
                else:
                    result = self._upload_part(
                        bucket_name=bucket_name,
                        object_name=object_name,
                        data=part_data,
                        headers=headers,
                        upload_id=upload_id,
                        part_number=part_number,
                    )
                    parts.append(Part(
                        part_number=part_number,
                        etag=result.etag,
                        checksum_crc32=result.checksum_crc32,
                        checksum_crc32c=result.checksum_crc32c,
                        checksum_sha1=result.checksum_sha1,
                        checksum_sha256=result.checksum_sha256,
                    ))

            if pool:
                result_queue = pool.result()
                parts = [Part(0, "")] * part_count
                while not result_queue.empty():
                    part_number, upload_result = result_queue.get()
                    parts[part_number - 1] = Part(
                        part_number=part_number,
                        etag=upload_result.etag,
                        checksum_crc32=upload_result.checksum_crc32,
                        checksum_crc32c=upload_result.checksum_crc32c,
                        checksum_sha1=upload_result.checksum_sha1,
                        checksum_sha256=upload_result.checksum_sha256,
                    )

            upload_result = self._complete_multipart_upload(
                bucket_name=bucket_name,
                object_name=object_name,
                upload_id=cast(str, upload_id),
                parts=parts,
                extra_headers=HTTPHeaderDict(
                    sse.headers() if isinstance(sse, SseCustomerKey) else None
                ),
            )
            return ObjectWriteResult.new(
                headers=upload_result.headers,
                bucket_name=cast(str, upload_result.bucket_name),
                object_name=cast(str, upload_result.object_name),
                version_id=upload_result.version_id,
                etag=upload_result.etag,
                location=upload_result.location,
            )
        except Exception as exc:
            if upload_id:
                self._abort_multipart_upload(
                    bucket_name=bucket_name,
                    object_name=object_name,
                    upload_id=upload_id,
                )
            raise exc

    def _append_object(
            self,
            bucket_name: str,
            object_name: str,
            stream: BinaryIO,
            chunk_size: int,
            length: Optional[int] = None,
            progress: Optional[ProgressType] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """Do append object."""
        chunk_count = -1
        if length is not None:
            chunk_count = max(int((length + chunk_size - 1) / chunk_size), 1)

        object_size = length
        uploaded_size = 0
        chunk_number = 0
        one_byte = b""
        stop = False

        stat = self.stat_object(
            bucket_name=bucket_name,
            object_name=object_name,
        )
        write_offset = cast(int, stat.size)

        while not stop:
            chunk_number += 1
            if chunk_count > 0:
                if chunk_number == chunk_count and object_size is not None:
                    chunk_size = object_size - uploaded_size
                    stop = True
                chunk_data = read_part_data(
                    stream=stream, size=chunk_size, progress=progress,
                )
                if len(chunk_data) != chunk_size:
                    raise IOError(
                        f"stream having not enough data;"
                        f"expected: {chunk_size}, "
                        f"got: {len(chunk_data)} bytes"
                    )
            else:
                chunk_data = read_part_data(
                    stream=stream,
                    size=chunk_size + 1,
                    part_data=one_byte,
                    progress=progress,
                )
                # If chunk_data_size is less or equal to chunk_size,
                # then we have reached last chunk.
                if len(chunk_data) <= chunk_size:
                    chunk_count = chunk_number
                    stop = True
                else:
                    one_byte = chunk_data[-1:]
                    chunk_data = chunk_data[:-1]

            uploaded_size += len(chunk_data)

            headers = HTTPHeaderDict(
                {"x-amz-write-offset-bytes": str(write_offset)},
            )
            upload_result = self._put_object(
                bucket_name=bucket_name,
                object_name=object_name,
                data=chunk_data,
                headers=headers,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            write_offset += len(chunk_data)
        return upload_result

    def append_object(
            self,
            bucket_name: str,
            object_name: str,
            data: Optional[bytes | BinaryIO] = None,
            length: Optional[int] = None,
            chunk_size: Optional[int] = None,
            progress: Optional[ProgressType] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            *,
            filename: Optional[str | os.PathLike] = None,
            stream: Optional[BinaryIO] = None,
            region: Optional[str] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """
        Append data to an existing object in a bucket.

        Only one of ``filename``, ``stream`` or ``data`` must be provided.
        If ``data`` is supplied, ``length`` must also be provided.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            filename (Optional[str | os.PathLike], default=None):
                Path to a file whose contents will be appended.

            stream (Optional[BinaryIO], default=None):
                An object with a callable ``read()`` method returning a
                bytes object.

            data (Optional[bytes], default=None):
                Raw data in a bytes object.

            length (Optional[int], default=None):
                Data length of ``data`` or ``stream``.

            chunk_size (Optional[int], default=None):
                Chunk size to split the data for appending.

            progress (Optional[ProgressType], default=None):
                Progress object to track upload progress.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectWriteResult:
                The result of the append operation.

        Example:
            >>> # Append simple data
            >>> result = client.append_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     data=io.BytesIO(b"world"),
            ...     length=5,
            ... )
            >>> print(f"appended {result.object_name} object; "
            ...      f"etag: {result.etag}")
            >>>
            >>> # Append data in chunks
            >>> with urlopen("https://www.kernel.org/pub/linux/kernel/v6.x/"
            ...              "linux-6.13.12.tar.xz") as stream:
            ...     result = client.append_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         stream=stream,
            ...         length=148611164,
            ...         chunk_size=5*1024*1024,
            ...     )
            >>> print(f"appended {result.object_name} object; "
            ...      f"etag: {result.etag}")
            >>>
            >>> # Append unknown-sized data
            >>> with urlopen("https://www.kernel.org/pub/linux/kernel/v6.x/"
            ...              "linux-6.14.3.tar.xz") as stream:
            ...     result = client.append_object(
            ...         bucket_name="my-bucket",
            ...         object_name="my-object",
            ...         stream=stream,
            ...         chunk_size=5*1024*1024,
            ...     )
            >>> print(f"appended {result.object_name} object; "
            ...      f"etag: {result.etag}")
        """
        if sum(x is not None for x in (filename, stream, data)) != 1:
            raise ValueError(
                "either filename, stream or data must be provided")
        if (length is not None and length <= 0):
            raise ValueError("valid length must be provided")
        if data is not None and length is None:
            raise ValueError("valid length must be provided for data")
        if chunk_size is not None:
            if chunk_size < MIN_PART_SIZE:
                raise ValueError("chunk size must be minimum of 5 MiB")
            if chunk_size > MAX_PART_SIZE:
                raise ValueError("chunk size must be less than 5 GiB")
        else:
            chunk_size = max(MIN_PART_SIZE, length or 0)

        if filename:
            file_size = os.stat(filename).st_size
            with open(filename, "rb") as file:
                return self._append_object(
                    bucket_name=bucket_name,
                    object_name=object_name,
                    stream=file,
                    length=file_size,
                    chunk_size=cast(int, chunk_size),
                    progress=progress,
                    region=region,
                    extra_headers=extra_headers,
                    extra_query_params=extra_query_params,
                )
        return self._append_object(
            bucket_name=bucket_name,
            object_name=object_name,
            stream=stream if stream else io.BytesIO(cast(bytes, data)),
            length=length,
            chunk_size=cast(int, chunk_size),
            progress=progress,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def list_objects(
            self,
            bucket_name: str,
            prefix: Optional[str] = None,
            recursive: bool = False,
            start_after: Optional[str] = None,
            include_user_meta: bool = False,
            include_version: bool = False,
            use_api_v1: bool = False,
            use_url_encoding_type: bool = True,
            fetch_owner: bool = False,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            *,
            region: Optional[str] = None,
    ) -> Iterator[Object]:
        """
        List object information of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            prefix (Optional[str], default=None):
                Return objects whose names start with this prefix.

            recursive (bool, default=False):
                List objects recursively instead of emulating directory
                structure.

            start_after (Optional[str], default=None):
                List objects after this key name.

            include_user_meta (bool, default=False):
                MinIO-specific flag to include user metadata.

            include_version (bool, default=False):
                Flag to include object versions in the listing.

            use_api_v1 (bool, default=False):
                Flag to use ListObjectsV1 S3 API instead of V2.

            use_url_encoding_type (bool, default=True):
                Flag to enable URL encoding for object names.

            fetch_owner (bool, default=False):
                Flag to fetch owner information of objects.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Iterator[Object]:
                An iterator of :class:`minio.datatypes.Object`.

        Example:
            >>> # List all objects in a bucket
            >>> objects = client.list_objects(bucket_name="my-bucket")
            >>> for obj in objects:
            ...     print(obj)
            >>>
            >>> # List objects with a prefix
            >>> objects = client.list_objects(
            ...     bucket_name="my-bucket", prefix="my/prefix/",
            ... )
            >>> for obj in objects:
            ...     print(obj)
            >>>
            >>> # List objects recursively
            >>> objects = client.list_objects(
            ...     bucket_name="my-bucket", recursive=True,
            ... )
            >>> for obj in objects:
            ...     print(obj)
            >>>
            >>> # Recursively list objects with a prefix
            >>> objects = client.list_objects(
            ...     bucket_name="my-bucket",
            ...     prefix="my/prefix/",
            ...     recursive=True,
            ... )
            >>> for obj in objects:
            ...     print(obj)
            >>>
            >>> # Recursively list objects after a specific key
            >>> objects = client.list_objects(
            ...     bucket_name="my-bucket",
            ...     recursive=True,
            ...     start_after="my/prefix/world/1",
            ... )
            >>> for obj in objects:
            ...     print(obj)
        """
        return self._list_objects(
            bucket_name=bucket_name,
            delimiter=None if recursive else "/",
            include_user_meta=include_user_meta,
            prefix=prefix,
            start_after=start_after,
            use_api_v1=use_api_v1,
            include_version=include_version,
            encoding_type="url" if use_url_encoding_type else None,
            fetch_owner=fetch_owner,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def stat_object(
            self,
            bucket_name: str,
            object_name: str,
            ssec: Optional[SseCustomerKey] = None,
            version_id: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            *,
            offset: int = 0,
            length: Optional[int] = None,
            match_etag: Optional[str] = None,
            not_match_etag: Optional[str] = None,
            modified_since: Optional[datetime] = None,
            unmodified_since: Optional[datetime] = None,
            fetch_checksum: bool = False,
            region: Optional[str] = None,
    ) -> Object:
        """
        Get object information and metadata of an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            ssec (Optional[SseCustomerKey], default=None):
                Server-side encryption customer key.

            offset (int, default=0):
                Start byte position of object data.

            length (Optional[int], default=None):
                Number of bytes of object data from offset.

            match_etag (Optional[str], default=None):
                Fetch only if the ETag of the object matches.

            not_match_etag (Optional[str], default=None):
                Fetch only if the ETag of the object does not match.

            modified_since (Optional[datetime], default=None):
                Fetch only if the object was modified since this date.

            unmodified_since (Optional[datetime], default=None):
                Fetch only if the object was unmodified since this date.

            fetch_checksum (bool, default=False):
                Flag to fetch the checksum of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Object:
                A :class:`minio.datatypes.Object` object containing metadata
                and information about the object.

        Example:
            >>> # Get object information
            >>> result = client.stat_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
            >>> print(f"last-modified: {result.last_modified}, "
            ...       f"size: {result.size}")
            >>>
            >>> # Get specific version of an object
            >>> result = client.stat_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
            ... )
            >>> print(f"last-modified: {result.last_modified}, "
            ...       f"size: {result.size}")
            >>>
            >>> # Get SSE-C encrypted object information
            >>> result = client.stat_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     ssec=SseCustomerKey(
            ...         b"32byteslongsecretkeymustprovided"
            ...     ),
            ... )
            >>> print(f"last-modified: {result.last_modified}, "
            ...       f"size: {result.size}")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        check_ssec(ssec)

        headers = self._gen_read_headers(
            ssec=ssec,
            offset=offset,
            length=length,
            match_etag=match_etag,
            not_match_etag=not_match_etag,
            modified_since=modified_since,
            unmodified_since=unmodified_since,
            fetch_checksum=fetch_checksum,
        )
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        response = self._execute(
            method="HEAD",
            bucket_name=bucket_name,
            object_name=object_name,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

        value = response.headers.get("last-modified")
        if value is not None:
            last_modified = time.from_http_header(value)
        else:
            last_modified = None

        return Object(
            bucket_name,
            object_name,
            last_modified=last_modified,
            etag=response.headers.get("etag", "").replace('"', ""),
            size=int(response.headers.get("content-length", "0")),
            content_type=response.headers.get("content-type"),
            metadata=response.headers,
            version_id=response.headers.get("x-amz-version-id"),
        )

    def remove_object(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Remove an object from a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> # Remove object
            >>> client.remove_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
            >>>
            >>> # Remove a specific version of an object
            >>> client.remove_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        self._execute(
            method="DELETE",
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def _delete_objects(
            self,
            bucket_name: str,
            delete_object_list: list[DeleteObject],
            quiet: bool = False,
            bypass_governance_mode: bool = False,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> DeleteResult:
        """
        Delete multiple objects.

        :param bucket_name: Name of the bucket.
        :param delete_object_list: List of maximum 1000
            :class:`DeleteObject <DeleteObject>` object.
        :param quiet: quiet flag.
        :param bypass_governance_mode: Bypass Governance retention mode.
        :return: :class:`DeleteResult <DeleteResult>` object.
        """
        body = marshal(DeleteRequest(delete_object_list, quiet=quiet))
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        if bypass_governance_mode:
            headers["x-amz-bypass-governance-retention"] = "true"
        response = self._execute(
            method="POST",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"delete": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

        element = ET.fromstring(response.data.decode())
        return (
            DeleteResult([], [DeleteError.fromxml(element)])
            if element.tag.endswith("Error")
            else unmarshal(DeleteResult, response.data.decode())
        )

    def remove_objects(
            self,
            bucket_name: str,
            delete_object_list: Iterable[DeleteObject],
            bypass_governance_mode: bool = False,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Iterator[DeleteError]:
        """
        Remove multiple objects from a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            delete_object_list (Iterable[DeleteObject]):
                Iterable of :class:`minio.deleteobjects.DeleteObject`
                instances to be deleted.

            bypass_governance_mode (bool, default=False):
                Flag to bypass Governance retention mode.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Iterator[DeleteError]:
                An iterator of :class:`minio.deleteobjects.DeleteError`
                objects for any failures.

        Example:
            >>> # Remove a list of objects
            >>> errors = client.remove_objects(
            ...     bucket_name="my-bucket",
            ...     delete_object_list=[
            ...         DeleteObject(name="my-object1"),
            ...         DeleteObject(name="my-object2"),
            ...         DeleteObject(
            ...             name="my-object3",
            ...             version_id="13f88b18-8dcd-4c83-88f2-8631fdb6250c",
            ...         ),
            ...     ],
            ... )
            >>> for error in errors:
            ...     print("error occurred when deleting object", error)
            >>>
            >>> # Remove objects under a prefix recursively
            >>> delete_object_list = map(
            ...     lambda x: DeleteObject(x.object_name),
            ...     client.list_objects(
            ...         bucket_name="my-bucket",
            ...         prefix="my/prefix/",
            ...         recursive=True,
            ...     ),
            ... )
            >>> errors = client.remove_objects(
            ...     bucket_name="my-bucket",
            ...     delete_object_list=delete_object_list,
            ... )
            >>> for error in errors:
            ...     print("error occurred when deleting object", error)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)

        # turn list like objects into an iterator.
        delete_object_list = itertools.chain(delete_object_list)

        while True:
            # get 1000 entries or whatever available.
            objects = [
                delete_object for _, delete_object in zip(
                    range(1000), delete_object_list,
                )
            ]

            if not objects:
                break

            result = self._delete_objects(
                bucket_name=bucket_name,
                delete_object_list=objects,
                quiet=True,
                bypass_governance_mode=bypass_governance_mode,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )

            for error in result.error_list:
                # AWS S3 returns "NoSuchVersion" error when
                # version doesn't exist ignore this error
                # yield all errors otherwise
                if error.code != "NoSuchVersion":
                    yield error

    def get_presigned_url(
            self,
            method: str,
            bucket_name: str,
            object_name: str,
            expires: timedelta = timedelta(days=7),
            response_headers: Optional[HTTPHeaderDict] = None,
            request_date: Optional[datetime] = None,
            version_id: Optional[str] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            *,
            region: Optional[str] = None,
    ) -> str:
        """
        Get a presigned URL for an object.

        The presigned URL can be used to perform the specified HTTP method
        on an object, with a custom expiry time and optional query
        parameters.

        Args:
            method (str):
                HTTP method to allow (e.g., "GET", "PUT", "DELETE").

            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            expires (timedelta, default=timedelta(days=7)):
                Expiry duration for the presigned URL.

            request_date (Optional[datetime], default=None):
                Request time to base the URL on, instead of the current
                time.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            str:
                A presigned URL string.

        Example:
            >>> # Generate presigned URL to delete object
            >>> url = client.get_presigned_url(
            ...     method="DELETE",
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     expires=timedelta(days=1),
            ... )
            >>> print(url)
            >>>
            >>> # Generate presigned URL to upload object with response type
            >>> url = client.get_presigned_url(
            ...     method="PUT",
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     expires=timedelta(days=1),
            ...     extra_query_params=HTTPQueryDict(
            ...         {"response-content-type": "application/json"}
            ...     ),
            ... )
            >>> print(url)
            >>>
            >>> # Generate presigned URL to download object
            >>> url = client.get_presigned_url(
            ...     method="GET",
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     expires=timedelta(hours=2),
            ... )
            >>> print(url)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        if expires.total_seconds() < 1 or expires.total_seconds() > 604800:
            raise ValueError("expires must be between 1 second to 7 days")

        region = self._get_region(bucket_name=bucket_name, region=region)
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        extra_query = HTTPQueryDict()
        if extra_query_params:
            extra_query.extend(extra_query_params)
        if response_headers:
            extra_query.extend(response_headers)
        creds = self._provider.retrieve() if self._provider else None
        if creds and creds.session_token:
            query_params["X-Amz-Security-Token"] = creds.session_token
        url = self._base_url.build(
            method=method,
            region=region,
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
            extra_query_params=extra_query,
        )

        if creds:
            url = presign_v4(
                method=method,
                url=url,
                region=region,
                credentials=creds,
                date=request_date or time.utcnow(),
                expires=int(expires.total_seconds()),
            )
        return urlunsplit(url)

    def presigned_get_object(
            self,
            bucket_name: str,
            object_name: str,
            expires: timedelta = timedelta(days=7),
            response_headers: Optional[HTTPHeaderDict] = None,
            request_date: Optional[datetime] = None,
            version_id: Optional[str] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
            *,
            region: Optional[str] = None,
    ) -> str:
        """
        Get a presigned URL to download an object.

        The presigned URL allows downloading an object's data with a custom
        expiry time and optional query parameters.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            expires (timedelta, default=timedelta(days=7)):
                Expiry duration for the presigned URL.

            request_date (Optional[datetime], default=None):
                Request time to base the URL on, instead of the current
                time.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            str:
                A presigned URL string.

        Example:
            >>> # Get presigned URL to download with default expiry (7 days)
            >>> url = client.presigned_get_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
            >>> print(url)
            >>>
            >>> # Get presigned URL to download with 2-hour expiry
            >>> url = client.presigned_get_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     expires=timedelta(hours=2),
            ... )
            >>> print(url)
        """
        return self.get_presigned_url(
            method="GET",
            bucket_name=bucket_name,
            object_name=object_name,
            expires=expires,
            response_headers=response_headers,
            request_date=request_date,
            version_id=version_id,
            region=region,
            extra_query_params=extra_query_params,
        )

    def presigned_put_object(
            self,
            bucket_name: str,
            object_name: str,
            expires: timedelta = timedelta(days=7),
            *,
            region: Optional[str] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> str:
        """
        Get a presigned URL to upload an object.

        The presigned URL allows uploading data to an object with a custom
        expiry time and optional query parameters.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            expires (timedelta, default=timedelta(days=7)):
                Expiry duration for the presigned URL.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            str:
                A presigned URL string.

        Example:
            >>> # Get presigned URL to upload with default expiry (7 days)
            >>> url = client.presigned_put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
            >>> print(url)
            >>>
            >>> # Get presigned URL to upload with 2-hour expiry
            >>> url = client.presigned_put_object(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     expires=timedelta(hours=2),
            ... )
            >>> print(url)
        """
        return self.get_presigned_url(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            expires=expires,
            region=region,
            extra_query_params=extra_query_params,
        )

    def presigned_post_policy(self, policy: PostPolicy) -> dict[str, str]:
        """
        Get form-data for a PostPolicy to upload an object using POST.

        Args:
            policy (PostPolicy):
                Post policy that defines conditions for the upload.

        Returns:
            dict[str, str]:
                A dictionary containing the form-data required for the POST
                request.

        Example:
            >>> policy = PostPolicy(
            ...     "my-bucket", datetime.utcnow() + timedelta(days=10),
            ... )
            >>> policy.add_starts_with_condition("key", "my/object/prefix/")
            >>> policy.add_content_length_range_condition(
            ...     1*1024*1024, 10*1024*1024,
            ... )
            >>> form_data = client.presigned_post_policy(policy)
        """
        if not isinstance(policy, PostPolicy):
            raise ValueError("policy must be PostPolicy type")
        if not self._provider:
            raise ValueError(
                "anonymous access does not require presigned post form-data",
            )
        check_bucket_name(
            policy.bucket_name, s3_check=self._base_url.is_aws_host)
        return policy.form_data(
            self._provider.retrieve(),
            self._get_region(bucket_name=policy.bucket_name),
        )

    def delete_bucket_replication(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the replication configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_bucket_replication(bucket_name="my-bucket")
        """
        self._execute_delete_bucket(
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"replication": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_bucket_replication(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Optional[ReplicationConfig]:
        """
        Get the replication configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Optional[ReplicationConfig]:
                A :class:`minio.replicationconfig.ReplicationConfig` object
                if replication is configured, otherwise ``None``.

        Example:
            >>> config = client.get_bucket_replication(bucket_name="my-bucket")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                query_params=HTTPQueryDict({"replication": ""}),
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            return unmarshal(ReplicationConfig, response.data.decode())
        except S3Error as exc:
            if exc.code != "ReplicationConfigurationNotFoundError":
                raise
        return None

    def set_bucket_replication(
            self,
            bucket_name: str,
            config: ReplicationConfig,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the replication configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            config (ReplicationConfig):
                Replication configuration to apply to the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> config = ReplicationConfig(
            ...     role="REPLACE-WITH-ACTUAL-ROLE",
            ...     rules=[
            ...         Rule(
            ...             destination=Destination(
            ...                 "REPLACE-WITH-ACTUAL-DESTINATION-BUCKET-ARN",
            ...             ),
            ...             status=ENABLED,
            ...             delete_marker_replication=DeleteMarkerReplication(
            ...                 DISABLED,
            ...             ),
            ...             rule_filter=Filter(
            ...                 AndOperator(
            ...                     "TaxDocs",
            ...                     {"key1": "value1", "key2": "value2"},
            ...                 ),
            ...             ),
            ...             rule_id="rule1",
            ...             priority=1,
            ...         ),
            ...     ],
            ... )
            >>> client.set_bucket_replication(
            ...     bucket_name="my-bucket",
            ...     config=config,
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(config, ReplicationConfig):
            raise ValueError("config must be ReplicationConfig type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"replication": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def delete_bucket_lifecycle(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the lifecycle configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_bucket_lifecycle(bucket_name="my-bucket")
        """
        self._execute_delete_bucket(
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"lifecycle": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_bucket_lifecycle(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Optional[LifecycleConfig]:
        """
        Get the lifecycle configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Optional[LifecycleConfig]:
                A :class:`minio.lifecycleconfig.LifecycleConfig` object if
                configured, otherwise ``None``.

        Example:
            >>> config = client.get_bucket_lifecycle(bucket_name="my-bucket")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                query_params=HTTPQueryDict({"lifecycle": ""}),
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            return unmarshal(LifecycleConfig, response.data.decode())
        except S3Error as exc:
            if exc.code != "NoSuchLifecycleConfiguration":
                raise
        return None

    def set_bucket_lifecycle(
            self,
            bucket_name: str,
            config: LifecycleConfig,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the lifecycle configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            config (LifecycleConfig):
                Lifecycle configuration to apply.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> config = LifecycleConfig(
            ...     [
            ...         Rule(
            ...             status=ENABLED,
            ...             rule_filter=Filter(prefix="documents/"),
            ...             rule_id="rule1",
            ...             transition=Transition(
            ...                 days=30,
            ...                 storage_class="GLACIER",
            ...             ),
            ...         ),
            ...         Rule(
            ...             status=ENABLED,
            ...             rule_filter=Filter(prefix="logs/"),
            ...             rule_id="rule2",
            ...             expiration=Expiration(days=365),
            ...         ),
            ...     ],
            ... )
            >>> client.set_bucket_lifecycle(
            ...     bucket_name="my-bucket",
            ...     config=config,
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(config, LifecycleConfig):
            raise ValueError("config must be LifecycleConfig type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"lifecycle": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def delete_bucket_tags(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the tags configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_bucket_tags(bucket_name="my-bucket")
        """
        self._execute_delete_bucket(
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"tagging": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_bucket_tags(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Optional[Tags]:
        """
        Get the tags configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Optional[Tags]:
                A :class:`minio.commonconfig.Tags` object if tags are
                configured, otherwise ``None``.

        Example:
            >>> tags = client.get_bucket_tags(bucket_name="my-bucket")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                query_params=HTTPQueryDict({"tagging": ""}),
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            tagging = unmarshal(Tagging, response.data.decode())
            return tagging.tags
        except S3Error as exc:
            if exc.code != "NoSuchTagSet":
                raise
        return None

    def set_bucket_tags(
            self,
            bucket_name: str,
            tags: Tags,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the tags configuration for a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            tags (Tags):
                Tags configuration as a
                :class:`minio.commonconfig.Tags` object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> tags = Tags.new_bucket_tags()
            >>> tags["Project"] = "Project One"
            >>> tags["User"] = "jsmith"
            >>> client.set_bucket_tags(bucket_name="my-bucket", tags=tags)
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        body = marshal(Tagging(tags))
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"tagging": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def delete_object_tags(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the tags configuration of an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_object_tags(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["tagging"] = ""
        self._execute(
            method="DELETE",
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_object_tags(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Optional[Tags]:
        """
        Get the tags configuration of an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Optional[Tags]:
                A :class:`minio.commonconfig.Tags` object if tags are
                configured, otherwise ``None``.

        Example:
            >>> tags = client.get_object_tags(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["tagging"] = ""
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                object_name=object_name,
                query_params=query_params,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            tagging = unmarshal(Tagging, response.data.decode())
            return tagging.tags
        except S3Error as exc:
            if exc.code != "NoSuchTagSet":
                raise
        return None

    def set_object_tags(
            self,
            bucket_name: str,
            object_name: str,
            tags: Tags,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the tags configuration for an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            tags (Tags):
                Tags configuration as a
                :class:`minio.commonconfig.Tags` object.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> tags = Tags.new_object_tags()
            >>> tags["Project"] = "Project One"
            >>> tags["User"] = "jsmith"
            >>> client.set_object_tags(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     tags=tags,
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        if not isinstance(tags, Tags):
            raise ValueError("tags must be Tags type")
        body = marshal(Tagging(tags))
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["tagging"] = ""
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def enable_object_legal_hold(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Enable legal hold on an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.enable_object_legal_hold(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        body = marshal(LegalHold(True))
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["legal-hold"] = ""
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def disable_object_legal_hold(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Disable legal hold on an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.disable_object_legal_hold(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        body = marshal(LegalHold(False))
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["legal-hold"] = ""
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def is_object_legal_hold_enabled(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> bool:
        """
        Check if legal hold is enabled on an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            bool:
                True if legal hold is enabled, False otherwise.

        Example:
            >>> if client.is_object_legal_hold_enabled(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... ):
            ...     print("legal hold is enabled on my-object")
            ... else:
            ...     print("legal hold is not enabled on my-object")
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["legal-hold"] = ""
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                object_name=object_name,
                query_params=query_params,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            legal_hold = unmarshal(LegalHold, response.data.decode())
            return legal_hold.status
        except S3Error as exc:
            if exc.code != "NoSuchObjectLockConfiguration":
                raise
        return False

    def delete_object_lock_config(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Delete the object-lock configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> client.delete_object_lock_config(bucket_name="my-bucket")
        """
        self.set_object_lock_config(
            bucket_name=bucket_name,
            config=ObjectLockConfig(None, None, None),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_object_lock_config(
            self,
            bucket_name: str,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectLockConfig:
        """
        Get the object-lock configuration of a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectLockConfig:
                A :class:`minio.objectlockconfig.ObjectLockConfig`
                object representing the bucket's object-lock
                configuration.

        Example:
            >>> config = client.get_object_lock_config(
            ...     bucket_name="my-bucket",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        response = self._execute(
            method="GET",
            bucket_name=bucket_name,
            query_params=HTTPQueryDict({"object-lock": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return unmarshal(ObjectLockConfig, response.data.decode())

    def set_object_lock_config(
            self,
            bucket_name: str,
            config: ObjectLockConfig,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the object-lock configuration for a bucket.

        Args:
            bucket_name (str):
                Name of the bucket.

            config (ObjectLockConfig):
                The object-lock configuration to apply.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> config = ObjectLockConfig(GOVERNANCE, 15, DAYS)
            >>> client.set_object_lock_config(
            ...     bucket_name="my-bucket",
            ...     config=config,
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        if not isinstance(config, ObjectLockConfig):
            raise ValueError("config must be ObjectLockConfig type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            body=body,
            headers=headers,
            query_params=HTTPQueryDict({"object-lock": ""}),
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def get_object_retention(
            self,
            bucket_name: str,
            object_name: str,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Optional[Retention]:
        """
        Get the retention information of an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            Optional[Retention]:
                A :class:`minio.retention.Retention` object if retention
                is set, otherwise ``None``.

        Example:
            >>> config = client.get_object_retention(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["retention"] = ""
        try:
            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                object_name=object_name,
                query_params=query_params,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
            return unmarshal(Retention, response.data.decode())
        except S3Error as exc:
            if exc.code != "NoSuchObjectLockConfiguration":
                raise
        return None

    def set_object_retention(
            self,
            bucket_name: str,
            object_name: str,
            config: Retention,
            version_id: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ):
        """
        Set the retention information for an object.

        Args:
            bucket_name (str):
                Name of the bucket.

            object_name (str):
                Object name in the bucket.

            config (Retention):
                Retention configuration.

            version_id (Optional[str], default=None):
                Version ID of the object.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Example:
            >>> config = Retention(
            ...     GOVERNANCE,
            ...     datetime.utcnow() + timedelta(days=10),
            ... )
            >>> client.set_object_retention(
            ...     bucket_name="my-bucket",
            ...     object_name="my-object",
            ...     config=config,
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)
        check_object_name(object_name)
        if not isinstance(config, Retention):
            raise ValueError("config must be Retention type")
        body = marshal(config)
        headers = HTTPHeaderDict(
            {"Content-MD5": base64_string(MD5.hash(body))},
        )
        query_params = HTTPQueryDict()
        if version_id:
            query_params["versionId"] = version_id
        query_params["retention"] = ""
        self._execute(
            method="PUT",
            bucket_name=bucket_name,
            object_name=object_name,
            body=body,
            headers=headers,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def upload_snowball_objects(
            self,
            bucket_name: str,
            object_list: Iterable[SnowballObject],
            metadata: Optional[HTTPHeaderDict] = None,
            sse: Optional[Sse] = None,
            tags: Optional[Tags] = None,
            retention: Optional[Retention] = None,
            legal_hold: bool = False,
            staging_filename: Optional[str] = None,
            compression: bool = False,
            *,
            headers: Optional[HTTPHeaderDict] = None,
            user_metadata: Optional[HTTPHeaderDict] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ObjectWriteResult:
        """
        Upload multiple objects in a single PUT call.

        This method creates an intermediate TAR file, optionally compressed,
        that is uploaded to the S3 service.

        Args:
            bucket_name (str):
                Name of the bucket.

            objects (Iterable[SnowballObject]):
                An iterable containing Snowball objects.

            headers (Optional[HTTPHeaderDict], default=None):
                Additional headers.

            user_metadata (Optional[HTTPHeaderDict], default=None):
                User metadata.

            sse (Optional[Sse], default=None):
                Server-side encryption.

            tags (Optional[Tags], default=None):
                Tags for the object.

            retention (Optional[Retention], default=None):
                Retention configuration.

            legal_hold (bool, default=False):
                Flag to set legal hold for the object.

            staging_filename (Optional[str], default=None):
                A staging filename to create the intermediate tarball.

            compression (bool, default=False):
                Flag to compress the tarball.

            region (Optional[str], default=None):
                Region of the bucket to skip auto probing.

            extra_headers (Optional[HTTPHeaderDict], default=None):
                Extra headers for advanced usage.

            extra_query_params (Optional[HTTPQueryDict], default=None):
                Extra query parameters for advanced usage.

        Returns:
            ObjectWriteResult:
                A :class:`minio.helpers.ObjectWriteResult` object.

        Example:
            >>> client.upload_snowball_objects(
            ...     bucket_name="my-bucket",
            ...     objects=[
            ...         SnowballObject(
            ...             object_name="my-object1",
            ...             filename="/etc/hostname",
            ...         ),
            ...         SnowballObject(
            ...             object_name="my-object2",
            ...             data=io.BytesIO(b"hello"),
            ...             length=5,
            ...         ),
            ...         SnowballObject(
            ...             object_name="my-object3",
            ...             data=io.BytesIO(b"world"),
            ...             length=5,
            ...             mod_time=datetime.now(),
            ...         ),
            ...     ],
            ... )
        """
        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)

        object_name = f"snowball.{random()}.tar"

        if user_metadata is None:
            user_metadata = metadata

        # turn list like objects into an iterator.
        objects = itertools.chain(object_list)

        headers = HTTPHeaderDict() if headers is None else headers.copy()
        headers["X-Amz-Meta-Snowball-Auto-Extract"] = "true"

        name = staging_filename
        fileobj = None if name else BytesIO()
        with tarfile.open(
                name=name, mode="w:gz" if compression else "w", fileobj=fileobj,
        ) as tar:
            for obj in objects:
                if obj.filename:
                    tar.add(obj.filename, obj.object_name)
                else:
                    info = tarfile.TarInfo(obj.object_name)
                    info.size = cast(int, obj.length)
                    info.mtime = int(
                        time.to_float(obj.mod_time or time.utcnow()),
                    )
                    tar.addfile(info, obj.data)

        if not name:
            length = cast(BytesIO, fileobj).tell()
            cast(BytesIO, fileobj).seek(0)
        else:
            length = os.stat(name).st_size

        part_size = 0 if length < MIN_PART_SIZE else length

        if name:
            return self.fput_object(
                bucket_name=bucket_name,
                object_name=object_name,
                file_path=cast(str, staging_filename),
                headers=headers,
                user_metadata=user_metadata,
                sse=sse,
                tags=tags,
                retention=retention,
                legal_hold=legal_hold,
                part_size=part_size,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )
        return self.put_object(
            bucket_name=bucket_name,
            object_name=object_name,
            data=cast(BinaryIO, fileobj),
            length=length,
            headers=headers,
            user_metadata=user_metadata,
            sse=sse,
            tags=tags,
            retention=retention,
            legal_hold=legal_hold,
            part_size=part_size,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )

    def _list_objects(
            self,
            bucket_name: str,
            continuation_token: Optional[str] = None,  # listV2 only
            delimiter: Optional[str] = None,  # all
            encoding_type: Optional[str] = None,  # all
            fetch_owner: Optional[bool] = None,  # listV2 only
            include_user_meta: bool = False,  # MinIO specific listV2.
            max_keys: Optional[int] = None,  # all
            prefix: Optional[str] = None,  # all
            start_after: Optional[str] = None,
            # all: v1:marker, versioned:key_marker
            version_id_marker: Optional[str] = None,  # versioned
            use_api_v1: bool = False,
            include_version: bool = False,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> Iterator[Object]:
        """
        List objects optionally including versions.
        Note: Its required to send empty values to delimiter/prefix and 1000 to
        max-keys when not provided for server-side bucket policy evaluation to
        succeed; otherwise AccessDenied error will be returned for such
        policies.
        """

        check_bucket_name(bucket_name, s3_check=self._base_url.is_aws_host)

        if version_id_marker:
            include_version = True

        is_truncated = True
        while is_truncated:
            query_params = HTTPQueryDict()
            if include_version:
                query_params["versions"] = ""
            elif not use_api_v1:
                query_params["list-type"] = "2"
            if not include_version and not use_api_v1:
                if continuation_token:
                    query_params["continuation-token"] = continuation_token
                if fetch_owner:
                    query_params["fetch-owner"] = "true"
                if include_user_meta:
                    query_params["metadata"] = "true"
            query_params["delimiter"] = delimiter or ""
            if encoding_type:
                query_params["encoding-type"] = encoding_type
            query_params["max-keys"] = str(max_keys or 1000)
            query_params["prefix"] = prefix or ""
            if start_after:
                if include_version:
                    query_params["key-marker"] = start_after
                elif use_api_v1:
                    query_params["marker"] = start_after
                else:
                    query_params["start-after"] = start_after
            if version_id_marker:
                query_params["version-id-marker"] = version_id_marker

            response = self._execute(
                method="GET",
                bucket_name=bucket_name,
                query_params=query_params,
                region=region,
                extra_headers=extra_headers,
                extra_query_params=extra_query_params,
            )

            objects, is_truncated, start_after, version_id_marker = (
                parse_list_objects(response)
            )

            if not include_version:
                version_id_marker = None
                if not use_api_v1:
                    continuation_token = start_after

            yield from objects

    def _list_multipart_uploads(
            self,
            bucket_name: str,
            delimiter: Optional[str] = None,
            encoding_type: Optional[str] = None,
            key_marker: Optional[str] = None,
            max_uploads: Optional[int] = None,
            prefix: Optional[str] = None,
            upload_id_marker: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ListMultipartUploadsResult:
        """
        Execute ListMultipartUploads S3 API.

        :param bucket_name: Name of the bucket.
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

        query_params = HTTPQueryDict(
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
            method="GET",
            bucket_name=bucket_name,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return ListMultipartUploadsResult(response)

    def _list_parts(
            self,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            max_parts: Optional[int] = None,
            part_number_marker: Optional[str] = None,
            region: Optional[str] = None,
            extra_headers: Optional[HTTPHeaderDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> ListPartsResult:
        """
        Execute ListParts S3 API.

        :param bucket_name: Name of the bucket.
        :param object_name: Object name in the bucket.
        :param upload_id: Upload ID.
        :param max_parts: (Optional) Maximum parts information to fetch.
        :param part_number_marker: (Optional) Part number marker.
        :param extra_headers: (Optional) Extra headers for advanced usage.
        :param extra_query_params: (Optional) Extra query parameters for
            advanced usage.
        :return: :class:`ListPartsResult <ListPartsResult>` object
        """

        query_params = HTTPQueryDict(
            {
                "uploadId": upload_id,
                "max-parts": str(max_parts or 1000),
            },
        )
        if part_number_marker:
            query_params["part-number-marker"] = part_number_marker

        response = self._execute(
            method="GET",
            bucket_name=bucket_name,
            object_name=object_name,
            query_params=query_params,
            region=region,
            extra_headers=extra_headers,
            extra_query_params=extra_query_params,
        )
        return ListPartsResult(response)
