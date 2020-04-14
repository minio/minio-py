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

from minio.credentials.static import Static
from minio.credentials.credentials import Value
from unittest import TestCase
from nose.tools import eq_


class StaticTest(TestCase):
    def test_static_credentials(self):
        # get provider
        provider = Static(
            access_key='UXHW',
            secret_key='SECRET'
        )
        # static is_expired is always False
        eq_(provider.is_expired(), False)
        # retrieve creds
        creds = provider.retrieve()
        expected_creds = Value(
            access_key='UXHW',
            secret_key='SECRET'
        )
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        # static is_expired is always False
        eq_(provider.is_expired(), False)

    def test_empty_static_credentials(self):
        # get provider
        provider = Static()
        # static is_expired is always False
        eq_(provider.is_expired(), False)
        # retrieve credentials
        creds = provider.retrieve()
        expected_creds = Value()
        eq_(creds.access_key, expected_creds.access_key)
        eq_(creds.secret_key, expected_creds.secret_key)
        eq_(creds.session_token, expected_creds.session_token)
        # static is_expired is always False
        eq_(provider.is_expired(), False)
