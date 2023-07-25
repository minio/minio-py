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
from minio.minioadminhttp import MinioAdminHttp

from .minio_mocks import MockConnection, MockResponse


class UserInfoTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    def test_user_info_works(self, mock_connection):
        access_key = "minioadmin"
        secret_key = "minioadmin"
        user = {
            'status': 'enabled',
            'memberOf': ['group', 'group2'],
            'policyName': 'policyA,policyB'
        }
        mock_data = json.dumps(user).encode()
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse('GET', 'https://localhost:9000/minio/admin/v3/user-info?accessKey=user',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         200, content=mock_data)
        )
        client = MinioAdminHttp('localhost:9000', access_key, secret_key)
        user = client.user_info('user')
        self.assertEqual('enabled', user.status)
        self.assertEqual('group2', user.member_of[1])
        self.assertEqual('policyA', user.policies[0])
