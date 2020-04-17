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

import json
import urllib3
import datetime

from .credentials import Provider, Value, Expiry
from minio.error import ResponseError
from .parsers import parse_iam_credentials


class IamEc2MetaData(Provider):
    iam_security_creds_path = '/latest/meta-data/iam/security-credentials'
    default_expiry_window = datetime.timedelta(minutes=5)

    def __init__(self, endpoint=None):
        super(Provider, self).__init__()
        self._endpoint = endpoint or "http://169.254.169.254"
        self._expiry = Expiry()
        self._http_client = urllib3.PoolManager(
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def request_cred_list(self):
        url = self._endpoint + self.iam_security_creds_path
        try:
            res = self._http_client.urlopen('GET', url)
            if res.status != 200:
                return None
        except:
            return None
        creds = res.data
        return creds.decode("utf-8").split('\n')

    def request_cred(self, creds_name):
        url = self._endpoint + self.iam_security_creds_path + "/" + creds_name
        res = self._http_client.urlopen('GET', url)
        if res.status != 200:
            raise ResponseError(res, 'GET')

        data = json.loads(res.data)
        if data['Code'] != 'Success':
            raise ResponseError(res, 'GET')

        return data

    def retrieve(self):
        role_names = self.request_cred_list()
        if not role_names:
            return Value()

        creds_name = role_names[0]
        role_creds = self.request_cred(creds_name)
        credentials_value, expiration = parse_iam_credentials(role_creds)

        self._expiry.set_expiration(expiration, self.default_expiry_window)

        return credentials_value

    def is_expired(self):
        return self._expiry.is_expired()
