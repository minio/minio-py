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

import os, json, urllib3, datetime
from .credentials import Provider, Value, Expiry
from minio.error import ResponseError

class IamEc2MetaData(Provider):

    iam_security_creds_path = '/latest/meta-data/iam/security-credentials'

    default_expiry_window = datetime.timedelta(minutes=5)

    def __init__(self, endpoint=None):
        super(Provider, self).__init__()
        if endpoint == "" or endpoint is None:
            endpoint = "http://169.254.169.254"
        self._endpoint = endpoint
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
            if res['status'] != 200:
                return []
        except:
            return []
        creds = res['data'].split('\n')
        return creds

    def request_cred(self, creds_name):
        url = self._endpoint + self.iam_security_creds_path + "/" + creds_name
        res = self._http_client.urlopen('GET', url)
        if res['status'] != 200:
            raise ResponseError(res, 'GET')

        data = json.loads(res['data'])
        if data['Code'] != 'Success':
            raise ResponseError(res)

        return data

    def retrieve(self):
        creds_list = self.request_cred_list()
        if len(creds_list) == 0:
            return Value()

        creds_name = creds_list[0]
        role_creds = self.request_cred(creds_name)
        expiration = datetime.datetime.strptime(role_creds['Expiration'], '%Y-%m-%dT%H:%M:%SZ')
        self._expiry.set_expiration(expiration, self.default_expiry_window)

        return Value(
            access_key=role_creds['AccessKeyId'],
            secret_key=role_creds['SecretAccessKey'],
            session_token=role_creds['Token']
        )

    def is_expired(self):
        return self._expiry.is_expired()
