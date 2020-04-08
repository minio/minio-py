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
from urllib.parse import urlencode

from minio import ResponseError
from minio.credentials import Credentials, Static

from minio.helpers import get_sha256_hexdigest
from minio.parsers import parse_assume_role
from minio.signer import sign_v4

# TODO work out the final api that minio-py developers want
# class AssumeRole(Credentials):
#     def __init__(self, mc, RoleArn=None, RoleSessionName=None, Policy=None, DurationSeconds=None):


def assume_role(mc, RoleArn=None, RoleSessionName=None, Policy=None, DurationSeconds=None):
    """"
    Generate temporary credentials using AssumeRole STS API.

    API documentation:
     - https://github.com/minio/minio/blob/master/docs/sts/assume-role.md
     - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html

    :param minio_client: Minio client needed to get endpoint, and credentials for the assume role request.
    :param RoleArn:
    :param RoleSessionName:
    :param Policy: Optional policy dict.
    :param DurationSeconds: Number of seconds the assume role credentials will remain valid.
    :return Credentials
    """
    region = 'us-east-1'
    method = 'POST'

    query = {
        "Action": "AssumeRole",
        "Version": "2011-06-15",
        "RoleArn": "arn:xxx:xxx:xxx:xxxx" if RoleArn is None else RoleArn,
        "RoleSessionName": "anything" if RoleSessionName is None else RoleSessionName,
    }

    # Add optional elements to the request
    if Policy is not None:
        query["Policy"] = Policy

    if DurationSeconds is not None:
        query["DurationSeconds"] = str(DurationSeconds)

    url = mc._endpoint_url + "/"
    content = urlencode(query)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'User-Agent': mc._user_agent
    }

    # Create signature headers
    content_sha256_hex = get_sha256_hexdigest(content)

    signed_headers = sign_v4(method, url, region, headers,
                             mc._credentials,
                             content_sha256=content_sha256_hex,
                             request_datetime=datetime.utcnow(),
                             service='sts'
                             )

    response = mc._http.urlopen(method, url, body=content, headers=signed_headers, preload_content=True)

    if response.status != 200:
        raise ResponseError(response, method).get_exception()

    # Parse the XML Response - getting the credentials as something convinient
    # Options include a credentials.Provider similar to Static, a Credentials instance, a Values instance.
    # For now to keep the xml parser low level I return a Values instance
    credentials_value, expiry = parse_assume_role(response.data)

    # TODO obviously don't keep this closure as the final api
    # need to work out what the api should actually be...
    class ExpiringProvider(Static):
        def is_expired(self):
            return datetime.now() > expiry

    credentials_provider = ExpiringProvider(access_key=credentials_value.access_key,
                                            secret_key=credentials_value.secret_key, token=credentials_value.session_token)
    return Credentials(provider=credentials_provider)

