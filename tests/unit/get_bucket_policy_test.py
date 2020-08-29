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
from unittest import TestCase

import mock
from nose.tools import eq_, raises

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT
from minio.error import S3Error
from tests.unit.minio_mocks import MockConnection, MockResponse


class GetBucketPolicyTest(TestCase):
    @mock.patch('urllib3.PoolManager')
    @raises(S3Error)
    def test_get_policy_for_non_existent_bucket(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        bucket_name = 'non-existent-bucket'
        error = ("<ErrorResponse>"
                 "<Code>NoSuchBucket</Code>"
                 "<Message>No such bucket</Message><RequestId>1234</RequestId>"
                 "<Resource>/non-existent-bucket</Resource>"
                 "<HostId>abcd</HostId>"
                 "<BucketName>non-existent-bucket</BucketName>"
                 "</ErrorResponse>")
        mock_server.mock_add_request(
            MockResponse(
                'GET',
                'https://localhost:9000/' + bucket_name + '?policy=',
                {'User-Agent': _DEFAULT_USER_AGENT},
                404,
                response_headers={"Content-Type": "application/xml"},
                content=error.encode()
            )
        )
        client = Minio('localhost:9000')
        client.get_bucket_policy(bucket_name)

    @mock.patch('urllib3.PoolManager')
    def test_get_policy_for_existent_bucket(self, mock_connection):
        mock_data = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetBucketLocation",
                    "Resource": "arn:aws:s3:::test-bucket"
                },
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::test-bucket"
                },
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*"
                }
            ]
        }).encode()
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        bucket_name = 'test-bucket'
        mock_server.mock_add_request(
            MockResponse(
                'GET',
                'https://localhost:9000/' + bucket_name + '?policy=',
                {'User-Agent': _DEFAULT_USER_AGENT},
                200,
                content=mock_data
            )
        )
        client = Minio('localhost:9000')
        response = client.get_bucket_policy(bucket_name)
        eq_(response, mock_data.decode())
