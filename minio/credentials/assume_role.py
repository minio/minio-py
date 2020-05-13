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
from minio.helpers import get_sha256_hexdigest
from minio.signer import sign_v4

from .credentials import Expiry, Provider


class AssumeRoleProvider(Provider):
    # AWS STS support GET and POST requests for all actions. That is, the API does not require you to
    # use GET for some actions and POST for others. However, GET requests are subject to the limitation
    # size of a URL; although this limit is browser dependent, a typical limit is 2048 bytes. Therefore,
    # for Query API requests that require larger sizes, you must use a POST request.

    def __init__(self, get_assume_role_creds):
        self._expiry = Expiry()
        self.get_assume_role_creds = get_assume_role_creds
        super(Provider, self).__init__()

    def retrieve(self):
        credentials_value, expiry = self.get_assume_role_creds()
        self._expiry.set_expiration(expiry)
        return credentials_value

    def is_expired(self):
        return self._expiry.is_expired()
