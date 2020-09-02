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
import os
from datetime import datetime, timedelta
from unittest import TestCase

import mock
from nose.tools import eq_, raises

from minio.credentials.credentials import Credentials
from minio.credentials.providers import (AWSConfigProvider, ChainedProvider,
                                         EnvAWSProvider, EnvMinioProvider,
                                         IamAwsProvider,
                                         MinioClientConfigProvider,
                                         StaticProvider)

CONFIG_JSON_SAMPLE = "tests/unit/config.json.sample"
CREDENTIALS_SAMPLE = "tests/unit/credentials.sample"
CREDENTIALS_EMPTY = "tests/unit/credentials.empty"


class CredentialsTest(TestCase):
    def test_credentials_get(self):
        provider = MinioClientConfigProvider(
            filename=CONFIG_JSON_SAMPLE,
            alias="play",
        )
        creds = provider.retrieve()
        eq_(creds.access_key, "Q3AM3UQ867SPQQA43P2F")
        eq_(creds.secret_key, "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
        eq_(creds.session_token, None)


class CredListResponse(object):
    status = 200
    data = b"test-s3-full-access-for-minio-ec2"


class CredsResponse(object):
    status = 200
    data = json.dumps({
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "accessKey",
        "SecretAccessKey": "secret",
        "Token": "token",
        "Expiration": "2014-12-16T01:51:37Z",
        "LastUpdated": "2009-11-23T0:00:00Z"
    })


class IamAwsProviderTest(TestCase):
    @mock.patch("urllib3.PoolManager.urlopen")
    def test_iam(self, mock_connection):
        mock_connection.side_effect = [CredListResponse(), CredsResponse()]
        provider = IamAwsProvider()
        creds = provider.retrieve()
        eq_(creds.access_key, "accessKey")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, "token")
        eq_(creds._expiration, datetime(2014, 12, 16, 1, 51, 37))


class ChainedProviderTest(TestCase):
    def test_chain_retrieve(self):
        # clear environment
        os.environ.clear()
        # prepare env for env_aws provider
        os.environ["AWS_ACCESS_KEY_ID"] = "access_aws"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret_aws"
        os.environ["AWS_SESSION_TOKEN"] = "token_aws"
        # prepare env for env_minio
        os.environ["MINIO_ACCESS_KEY"] = "access_minio"
        os.environ["MINIO_SECRET_KEY"] = "secret_minio"
        # create chain provider with env_aws and env_minio providers

        provider = ChainedProvider(
            [
                EnvAWSProvider(), EnvMinioProvider(),
            ]
        )
        # retireve provider (env_aws) has priority
        creds = provider.retrieve()
        # assert provider credentials
        eq_(creds.access_key, "access_aws")
        eq_(creds.secret_key, "secret_aws")
        eq_(creds.session_token, "token_aws")


class EnvAWSProviderTest(TestCase):
    def test_env_aws_retrieve(self):
        os.environ.clear()
        os.environ["AWS_ACCESS_KEY_ID"] = "access"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret"
        os.environ["AWS_SESSION_TOKEN"] = "token"
        provider = EnvAWSProvider()
        creds = provider.retrieve()
        eq_(creds.access_key, "access")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, "token")

    def test_env_aws_retrieve_no_token(self):
        os.environ.clear()
        os.environ["AWS_ACCESS_KEY_ID"] = "access"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret"
        provider = EnvAWSProvider()
        creds = provider.retrieve()
        eq_(creds.access_key, "access")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, None)


class EnvMinioTest(TestCase):
    def test_env_minio_retrieve(self):
        os.environ.clear()
        os.environ['MINIO_ACCESS_KEY'] = "access"
        os.environ["MINIO_SECRET_KEY"] = "secret"
        provider = EnvMinioProvider()
        creds = provider.retrieve()
        eq_(creds.access_key, "access")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, None)


class AWSConfigProviderTest(TestCase):
    def test_file_aws(self):
        os.environ.clear()
        provider = AWSConfigProvider(CREDENTIALS_SAMPLE)
        creds = provider.retrieve()
        eq_(creds.access_key, "accessKey")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, "token")

    def test_file_aws_from_env(self):
        os.environ.clear()
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = (
            CREDENTIALS_SAMPLE
        )
        provider = AWSConfigProvider()
        creds = provider.retrieve()
        eq_(creds.access_key, "accessKey")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, "token")

    def test_file_aws_env_profile(self):
        os.environ.clear()
        os.environ["AWS_PROFILE"] = "no_token"
        provider = AWSConfigProvider(CREDENTIALS_SAMPLE)
        creds = provider.retrieve()
        eq_(creds.access_key, "accessKey")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, None)

    def test_file_aws_arg_profile(self):
        os.environ.clear()
        provider = AWSConfigProvider(
            CREDENTIALS_SAMPLE,
            "no_token",
        )
        creds = provider.retrieve()
        eq_(creds.access_key, "accessKey")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, None)

    def test_file_aws_no_creds(self):
        os.environ.clear()
        provider = AWSConfigProvider(
            CREDENTIALS_EMPTY,
            "no_token",
        )
        try:
            provider.retrieve()
        except ValueError:
            pass


class MinioClientConfigProviderTest(TestCase):
    def test_file_minio_(self):
        os.environ.clear()
        provider = MinioClientConfigProvider(filename=CONFIG_JSON_SAMPLE)
        creds = provider.retrieve()
        eq_(creds.access_key, "accessKey")
        eq_(creds.secret_key, "secret")
        eq_(creds.session_token, None)

    def test_file_minio_env_alias(self):
        os.environ.clear()
        os.environ["MINIO_ALIAS"] = "play"
        provider = MinioClientConfigProvider(filename=CONFIG_JSON_SAMPLE)
        creds = provider.retrieve()
        eq_(creds.access_key, "Q3AM3UQ867SPQQA43P2F")
        eq_(creds.secret_key, "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
        eq_(creds.session_token, None)

    def test_file_minio_arg_alias(self):
        os.environ.clear()
        provider = MinioClientConfigProvider(
            filename=CONFIG_JSON_SAMPLE,
            alias="play",
        )
        creds = provider.retrieve()
        eq_(creds.access_key, "Q3AM3UQ867SPQQA43P2F")
        eq_(creds.secret_key, "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
        eq_(creds.session_token, None)


class StaticProviderTest(TestCase):
    def test_static_credentials(self):
        provider = StaticProvider("UXHW", "SECRET")
        creds = provider.retrieve()
        eq_(creds.access_key, "UXHW")
        eq_(creds.secret_key, "SECRET")
        eq_(creds.session_token, None)
