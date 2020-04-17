# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2020 MinIO, Inc.
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
from datetime import datetime

from minio.compat import urlencode
from minio.error import ResponseError
from minio.credentials import Credentials
from minio.helpers import get_sha256_hexdigest
from minio.signer import sign_v4

from .credentials import Expiry, Provider
from .parsers import parse_assume_role


class AssumeRoleProvider(Provider):
    region = 'us-east-1'

    # AWS STS support GET and POST requests for all actions. That is, the API does not require you to
    # use GET for some actions and POST for others. However, GET requests are subject to the limitation
    # size of a URL; although this limit is browser dependent, a typical limit is 2048 bytes. Therefore,
    # for Query API requests that require larger sizes, you must use a POST request.
    method = 'POST'

    def __init__(self, mc, RoleArn=None, RoleSessionName=None, Policy=None, DurationSeconds=None):
        self._minio_client = mc
        self._expiry = Expiry()
        self._DurationSeconds = DurationSeconds
        self._RoleArn = "arn:xxx:xxx:xxx:xxxx" if RoleArn is None else RoleArn
        self._RoleSessionName = "anything" if RoleSessionName is None else RoleSessionName
        self._Policy = Policy

        super(Provider, self).__init__()

    def retrieve(self):

        query = {
            "Action": "AssumeRole",
            "Version": "2011-06-15",
            "RoleArn": self._RoleArn,
            "RoleSessionName": self._RoleSessionName,
        }

        # Add optional elements to the request
        if self._Policy is not None:
            query["Policy"] = self._Policy

        if self._DurationSeconds is not None:
            query["DurationSeconds"] = str(self._DurationSeconds)

        url = self._minio_client._endpoint_url + "/"
        content = urlencode(query)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'User-Agent': self._minio_client._user_agent
        }

        # Create signature headers
        content_sha256_hex = get_sha256_hexdigest(content)
        signed_headers = sign_v4(self.method, url, self.region, headers,
                                 self._minio_client._credentials,
                                 content_sha256=content_sha256_hex,
                                 request_datetime=datetime.utcnow(),
                                 service_name='sts'
                                 )
        response = self._minio_client._http.urlopen(self.method, url,
                                                    body=content,
                                                    headers=signed_headers,
                                                    preload_content=True)

        if response.status != 200:
            raise ResponseError(response, self.method).get_exception()

        # Parse the XML Response - getting the credentials as a Values instance.
        credentials_value, expiry = parse_assume_role(response.data)
        self._expiry.set_expiration(expiry)

        return credentials_value

    def is_expired(self):
        return self._expiry.is_expired()
