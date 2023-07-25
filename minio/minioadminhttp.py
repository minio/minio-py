# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2021 MinIO, Inc.
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

# pylint: disable=too-many-public-methods

"""MinIO Admin wrapper using HTTP API."""

from __future__ import absolute_import
import json
from minio.api import HttpClient
from minio.crypto import decrypt, encrypt
from minio.datatypes import UserInfo, parse_list_users
from minio.error import AdminResponseError


_ADMIN_PATH_PREFIX = "/minio/admin/v3"


class MinioAdminHttp(HttpClient):
    """MinIO Admin wrapper using HTTP API"""

    def __init__(self, endpoint, access_key,
                 secret_key,
                 session_token=None,
                 secure=True,
                 region="us-east-1",
                 http_client=None,
                 credentials=None,
                 cert_check=True):
        super().__init__(endpoint, access_key, secret_key, session_token,
                         secure, region, http_client, credentials, cert_check)

    def _url_open(  # pylint: disable=too-many-branches
            self,
            method,
            path,
            body=None,
            headers=None,
            query_params=None,
    ):
        """Execute HTTP request."""
        url = self._base_url.build(
            method,
            region=self._base_url.region,
            bucket_name=None,
            object_name=None,
            query_params=query_params,
            path=_ADMIN_PATH_PREFIX + path
        )

        response = self._send_request(
            method,
            url,
            headers,
            body,
            region=self._base_url.region
        )

        if response.status in [200, 204, 206]:
            return response

        raise AdminResponseError(
            response.status,
            response.headers.get("content-type"),
            response.data.decode() if response.data else None
        )

    def user_add(self, access_key: str, secret_key: str):
        """Create user with access and secret keys"""
        params = {"accessKey": access_key}
        data = {"secretKey": secret_key}
        data = json.dumps(data).encode('utf-8')
        creds = self._provider.retrieve()
        data = encrypt(data, creds.secret_key)
        self._url_open("PUT", "/add-user", query_params=params, body=data)

    def user_info(self, access_key: str) -> UserInfo:
        """Get information about user"""
        params = {"accessKey": access_key}
        response = self._url_open("GET", "/user-info", query_params=params)
        data = response.data.decode()
        return UserInfo.fromjson(data)

    def list_users(self) -> dict[str, UserInfo]:
        """List all users"""
        response = self._url_open("GET", "/list-users")
        creds = self._provider.retrieve()
        data = decrypt(response.data, creds.secret_key).decode()
        return parse_list_users(data)

    def user_remove(self, access_key: str):
        """Delete user"""
        params = {"accessKey": access_key}
        self._url_open("DELETE", "/remove-user", query_params=params)
