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

# pylint: disable=too-many-lines,disable=too-many-branches,too-many-statements
# pylint: disable=too-many-arguments

"""HTTP client to perform authenticated requests to S3 services."""

from __future__ import absolute_import

import os
import platform
from datetime import timedelta
from urllib.parse import urlunsplit

import certifi
import urllib3
from urllib3._collections import HTTPHeaderDict

from . import __title__, __version__, time
from .credentials import StaticProvider
from .helpers import (BaseURL, md5sum_hash, sha256_hash)

from .signer import sign_v4_s3

_DEFAULT_USER_AGENT = (
    f"MinIO ({platform.system()}; {platform.machine()}) "
    f"{__title__}/{__version__}")


class HttpClient:
    """HTTP client to perform authenticated requests to S3 services."""

    def __init__(self, endpoint, access_key=None,
                 secret_key=None,
                 session_token=None,
                 secure=True,
                 region=None,
                 http_client=None,
                 credentials=None,
                 cert_check=True):
        # Validate http client has correct base class.
        if http_client and not isinstance(
                http_client,
                urllib3.poolmanager.PoolManager):
            raise ValueError(
                "HTTP client should be instance of "
                "`urllib3.poolmanager.PoolManager`"
            )

        self._base_url = BaseURL(
            ("https://" if secure else "http://") + endpoint,
            region,
        )
        self._user_agent = _DEFAULT_USER_AGENT
        if access_key:
            credentials = StaticProvider(access_key, secret_key, session_token)
        self._provider = credentials

        # Load CA certificates from SSL_CERT_FILE file if set
        timeout = timedelta(minutes=5).seconds
        self._http = http_client or urllib3.PoolManager(
            timeout=urllib3.util.Timeout(connect=timeout, read=timeout),
            maxsize=10,
            cert_reqs='CERT_REQUIRED' if cert_check else 'CERT_NONE',
            ca_certs=os.environ.get('SSL_CERT_FILE') or certifi.where(),
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def __del__(self):
        self._http.clear()

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
        date = time.utcnow()
        headers["x-amz-date"] = time.to_amz_date(date)
        return headers, date

    def _build_signed_headers(self, url, headers, body, creds, method, region):
        """Build signed headers"""
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

        return headers

    def _send_request(self, method, url, headers, body,
                      region=None,
                      preload_content=True):
        """Send HTTP request with given parameters"""
        creds = self._provider.retrieve() if self._provider else None

        headers = self._build_signed_headers(
            url,
            headers,
            body,
            creds,
            method,
            region
        )

        return self._http.urlopen(
            method,
            urlunsplit(url),
            body=body,
            headers=convert_to_urllib3_headers(headers),
            preload_content=preload_content,
        )


def convert_to_urllib3_headers(headers):
    """Convert headers to urllib3 format"""
    http_headers = HTTPHeaderDict()
    for key, value in (headers or {}).items():
        if isinstance(value, (list, tuple)):
            _ = [http_headers.add(key, val) for val in value]
        else:
            http_headers.add(key, value)
    return http_headers
