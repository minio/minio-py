# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2020 MinIO, Inc.
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

import json

import urllib3

from minio import Minio
from minio.credentials import ClientGrantsProvider


def get_jwt(client_id, client_secret, idp_endpoint):
    res = urllib3.PoolManager().request(
        "POST",
        idp_endpoint,
        fields={
            "username": client_id,
            "password": client_secret,
            "grant_type": "client_credentials",
        },
    )

    return json.loads(res.data.encode())


# IDP endpoint.
idp_endpoint = (
    "https://IDP-HOST:IDP-PORT/auth/realms/master"
    "/protocol/openid-connect/token"
)

# Client-ID to fetch JWT.
client_id = "USER-ID"

# Client secret to fetch JWT.
client_secret = "PASSWORD"

# STS endpoint usually point to MinIO server.
sts_endpoint = "http://STS-HOST:STS-PORT/"

provider = ClientGrantsProvider(
    lambda: get_jwt(client_id, client_secret, idp_endpoint), sts_endpoint,
)

client = Minio("MINIO-HOST:MINIO-PORT", credentials=provider)

# Get information of an object.
stat = client.stat_object("my-bucket", "my-object")
print(stat)
