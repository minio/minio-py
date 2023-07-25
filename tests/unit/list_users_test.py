# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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
import unittest.mock as mock
from unittest import TestCase

from minio.api import _DEFAULT_USER_AGENT
from minio.crypto import encrypt
from minio.minioadminhttp import MinioAdminHttp

from .minio_mocks import MockConnection, MockResponse


class ListUsersTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_empty_list_users_works(self, mock_connection):
        access_key = "minioadmin"
        secret_key = "minioadmin"
        mock_data = encrypt(json.dumps({}).encode(), secret_key)
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET', 'https://localhost:9000/minio/admin/v3/list-users',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         200, content=mock_data)
        )
        client = MinioAdminHttp('localhost:9000', access_key, secret_key)
        users = client.list_users()
        self.assertEqual(0, len(users))

    @mock.patch('urllib3.PoolManager')
    def test_list_users_works(self, mock_connection):
        access_key = "minioadmin"
        secret_key = "minioadmin"
        users = {
            'john': {
                'status': 'enabled',
                'memberOf': ['group', 'group2'],
                'policyName': 'policyA,policyB'
            },
            'matt': {
                'status': 'disabled',
                'memberOf': ['group2', 'group1', 'group3'],
                'policyName': ''
            }
        }
        mock_data = encrypt(json.dumps(users).encode(), secret_key)
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET', 'https://localhost:9000/minio/admin/v3/list-users',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         200, content=mock_data)
        )
        client = MinioAdminHttp('localhost:9000', access_key, secret_key)
        users = client.list_users()
        self.assertEqual(2, len(users))
        self.assertEqual(2, len(users['john'].policies))
        self.assertEqual(0, len(users['matt'].policies))
        self.assertEqual(3, len(users['matt'].member_of))

        self.assertEqual('disabled', users['matt'].status)
        self.assertEqual('policyB', users['john'].policies[1])
        self.assertEqual('group1', users['matt'].member_of[1])
