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

import os
from unittest import TestCase

from minio.credentials.chain import Chain
from minio.credentials.env_aws import EnvAWS
from minio.credentials.env_minio import EnvMinio
from nose.tools import eq_


class ChainProviderTest(TestCase):

    def test_chain_retrieve(self):
        # clear environment
        os.environ.clear()
        # prepare env for env_aws provider
        os.environ["AWS_ACCESS_KEY_ID"] = "access_aws"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret_aws"
        os.environ["AWS_SESSION_TOKEN"] = "token_aws"
        # prepare env for env_minio
        os.environ['MINIO_ACCESS_KEY'] = "access_minio"
        os.environ["MINIO_SECRET_KEY"] = "secret_minio"
        # create chain provider with env_aws and env_minio providers
        chain = Chain(
            providers=[
                EnvAWS(),
                EnvMinio()
            ]
        )
        # retireve provider (env_aws) has priority
        creds = chain.retrieve()
        # assert provider credentials
        eq_(creds.access_key, "access_aws")
        eq_(creds.secret_key, "secret_aws")
        eq_(creds.session_token, "token_aws")
        # assert is_expired
        eq_(chain.is_expired(), False)

    def test_chain_is_expired(self):
        # clear environment
        os.environ.clear()
        # prepare env for env_aws
        os.environ["AWS_ACCESS_KEY_ID"] = "access_aws"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret_aws"
        # create chain provider
        chain = Chain(
            providers=[EnvAWS()]
        )
        # is_expired should be True before retrieve()
        eq_(chain.is_expired(), True)
        # retieve single env_aws provider
        chain.retrieve()
        # is_expired should be False after retrieve()
        eq_(chain.is_expired(), False)

    def test_chain_with_no_provider(self):
        # clear environment
        os.environ.clear()
        # create empty chain provider
        chain = Chain(
            providers=[]
        )
        # is_expired should be True before retrieve()
        eq_(chain.is_expired(), True)
