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

import os

from unittest import TestCase
from minio.credentials.file_minio_client import FileMinioClient
from minio.credentials.credentials import Value

from nose.tools import eq_


class FileMinioClientTest(TestCase):

    def test_file_minio_(self):
        # clear environment
        os.environ.clear()
        # get provider
        provider = FileMinioClient('minio/credentials/config.json.sample')
        # is_expired should be True before retrieve
        eq_(provider.is_expired(), True)
        # retrieve credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='accessKey',
            secret_key='secret',
            session_token=None
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False after retrieve
        eq_(provider.is_expired(), False)

    def test_file_minio_env_alias(self):
        # clear environment
        os.environ.clear()
        # set env with minio config file
        os.environ['MINIO_ALIAS'] = 'play'
        # get provider
        provider = FileMinioClient('minio/credentials/config.json.sample')
        # is_expired should be True before retrieve
        eq_(provider.is_expired(), True)
        # retrieve credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='Q3AM3UQ867SPQQA43P2F',
            secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
            session_token=None
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired is False after retrieve
        eq_(provider.is_expired(), False)

    def test_file_minio_arg_alias(self):
        # clear environment
        os.environ.clear()
        # get provider
        provider = FileMinioClient(
            'minio/credentials/config.json.sample', 'play')
        # is_expired is True before retrieve
        eq_(provider.is_expired(), True)
        # get credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='Q3AM3UQ867SPQQA43P2F',
            secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
            session_token=None
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False after retrieve
        eq_(provider.is_expired(), False)
