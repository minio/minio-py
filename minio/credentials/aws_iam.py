# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017, 2018, 2019 MinIO, Inc.
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


class IAM(Provider):

    iam_security_creds_path = '/latest/meta-data/iam/security-credentials'

    default_expiry_window = 10 # 10 seconds

    def __init__(self, expiry=None, endpoint=None):
        # TODO How to init expiry
        super(IAM, self).__init__()
        if endpoint == "" or None:
            endpoint = "http://169.254.169.254"
        self._endpoint = endpoint
        self._expiry = Expiry()
        #TODO Hoe to deal with client
        self._http_client = urllib3.PoolManager(
                retries=urllib3.Retry(
                    total=5,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                    )
                )

    def request_cred_list(self):
        url = self.endpoint + self.iam_security_creds_path
        res = self._http_client.urlopen('GET', url)
        if res.status != 200:
            #TODO: how to handle errors
            raise
        creds = res.data.split('\n')
        return creds

    def request_cred(self, creds_name):
        url = self._endpoint + self.iam_security_creds_path + "/" + creds_name
        res = self._http_client.urlopen('GET', url)
        if res.status != 200:
            #TODO how to handle errors
            raise

        data = json.loads(res.data)
        if data['Code'] != 'Success':
            raise

        return data

    def retrieve(self):
        # request credentials from the EC2 service
        creds_list = self.request_cred_list()
        # Get credential name
        # TODO rolename
        if len(creds_list) == 0:
            # TODO: how to handle error
            raise

        creds_name = creds_list[0]
        role_creds = self.request_cred(creds_name)
        
        self._expiry.set_expiration(role_creds.Expiration, self.default_expiry_window)

        return Value(
            access_key=role_creds.accessKeyId,
            secret_key=role_creds.secretAccessKey,
            session_token=role_creds.token
        )
    def is_expired(self):
        if self._expiry_window is None:
            return True
        return self._expiry_window < datetime.datetime.now()