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
                                 service='sts'
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


def assume_role(mc, RoleArn=None, RoleSessionName=None, Policy=None, DurationSeconds=None):
    """"
    Generate temporary credentials using AssumeRole STS API.

    API documentation:
     - https://github.com/minio/minio/blob/master/docs/sts/assume-role.md
     - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html

    :param minio_client: Minio client needed to get endpoint, and credentials for the assume role request.
    :param RoleArn: RoleArn is ignored by MinIO, but is required by boto and AWS STS.
    :param RoleSessionName: RoleSessionName is ignored by MinIO, but is required by boto and AWS STS.
    :param Policy: Optional policy dict.
    :param DurationSeconds: Number of seconds the assume role credentials will remain valid.
    :return Credentials
    """
    credentials_provider = AssumeRoleProvider(mc, RoleArn, RoleSessionName, Policy, DurationSeconds)
    return Credentials(provider=credentials_provider)

