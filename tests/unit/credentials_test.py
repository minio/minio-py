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

from minio.credentials.credentials import Credentials, Value
from minio.credentials.file_minio_client import FileMinioClient
from unittest import TestCase
from nose.tools import eq_


class CredentialsTest(TestCase):
    def test_credentials_get(self):
        # get credentials
        credentials = Credentials(
            provider=FileMinioClient(
                'minio/credentials/config.json.sample', 'play')
        )
        # is_expired should be True before get
        eq_(credentials.is_expired(), True)
        creds = credentials.get()
        expected_creds = Value(
            access_key='Q3AM3UQ867SPQQA43P2F',
            secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
            session_token=None
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False after get
        eq_(credentials.is_expired(), False)

    def test_credentials_with_error(self):
        pass
