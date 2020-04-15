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

from minio.credentials.file_aws_credentials import FileAWSCredentials
from minio.credentials.credentials import Value
from nose.tools import eq_


class FileAWSCredentialsTest(TestCase):

    def test_file_aws(self):
        # clear environment
        os.environ.clear()
        # get provider
        provider = FileAWSCredentials('minio/credentials/credentials.sample')
        # is_expired should be True before retrieve
        eq_(provider.is_expired(), True)
        # retrieve credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='accessKey',
            secret_key='secret',
            session_token='token'
        )
        # assert credentials
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False before retrieve
        eq_(provider.is_expired(), False)

    def test_file_aws_from_env(self):
        # clear environment
        os.environ.clear()
        # set env with aws config file
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = (
            'minio/credentials/credentials.sample')
        # get provider
        provider = FileAWSCredentials()
        # is_expired should be True before retrieve
        eq_(provider.is_expired(), True)
        # retieve credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='accessKey',
            secret_key='secret',
            session_token='token'
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False after retrieve
        eq_(provider.is_expired(), False)

    def test_file_aws_env_profile(self):
        # clear environment
        os.environ.clear()
        # set profile env
        os.environ['AWS_PROFILE'] = 'no_token'
        # get provider
        provider = FileAWSCredentials('minio/credentials/credentials.sample')
        # is_expired should be True before retrieve
        eq_(provider.is_expired(), True)
        # retrieve credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='accessKey',
            secret_key='secret',
            session_token=''
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False after retrieve
        eq_(provider.is_expired(), False)

    def test_file_aws_arg_profile(self):
        # clear environment
        os.environ.clear()
        # get provider
        provider = FileAWSCredentials(
            'minio/credentials/credentials.sample', 'no_token')
        # is_expired should be True before retrieve
        eq_(provider.is_expired(), True)
        # retrieve credentials
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='accessKey',
            secret_key='secret',
            session_token=''
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # is_expired should be False after retieve
        eq_(provider.is_expired(), False)

    def test_file_aws_no_creds(self):
        # clear environment
        os.environ.clear()
        provider = FileAWSCredentials(
            'minio/credentials/credentials.empty', 'no_token')
        creds = provider.retrieve()
        eq_(creds.access_key, None)
        eq_(creds.secret_key, None)
        eq_(creds.session_token, None)
