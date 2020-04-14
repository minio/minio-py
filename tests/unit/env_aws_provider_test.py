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

from minio.credentials.env_aws import EnvAWS
from minio.credentials.credentials import Value
from nose.tools import eq_


class EnvAWSTest(TestCase):

    def test_env_aws_retrieve(self):
        # clear environement
        os.environ.clear()
        # set environment variables
        os.environ["AWS_ACCESS_KEY_ID"] = "access"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret"
        os.environ["AWS_SESSION_TOKEN"] = "token"
        # init new env_aws provider
        provider = EnvAWS()
        # assert expired true for newly created provider
        eq_(provider.is_expired(), True)
        # retrieve provider credentials
        creds = provider.retrieve()
        # assert expected data
        expected_creds = Value(
            access_key="access",
            secret_key="secret",
            session_token="token"
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # assert expired true for retrieved credentials
        eq_(provider.is_expired(), False)

    def test_env_aws_retrieve_no_token(self):
        # clear environement
        os.environ.clear()
        # set environment variables
        os.environ["AWS_ACCESS_KEY_ID"] = "access"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret"
        # Init new env_aws provider
        provider = EnvAWS()
        # assert expired true for newly created provider
        eq_(provider.is_expired(), True)
        # retrieve rpovider credentials
        creds = provider.retrieve()
        # assert expected data
        expected_creds = Value(
            access_key="access",
            secret_key="secret",
            session_token=None
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # assert expired true for retrieved credentials
        eq_(provider.is_expired(), False)
