# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 MinIO, Inc.
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

import mock

from unittest import TestCase
from nose.tools import raises

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT
from minio.error import InvalidArgumentError

from .minio_mocks import MockResponse, MockConnection

class SetBucketNotificationTest(TestCase):
    @raises(TypeError)
    def test_notification_is_dict_1(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification('my-test-bucket', 'abc')

    @raises(TypeError)
    def test_notification_is_dict_2(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification('my-test-bucket', ['myconfig1'])

    @raises(InvalidArgumentError)
    def test_notification_config_is_nonempty(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {}
        )

    @raises(InvalidArgumentError)
    def test_notification_config_has_valid_keys(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfiguration': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_arn_key_is_present(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Events': ['s3:ObjectCreated:*'],
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_id_key_is_string(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': 1,
                        'Arn': 'abc',
                        'Events': ['s3:ObjectCreated:*'],
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_events_key_is_present(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_event_values_are_valid(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['object_created']
                    }
                ]
            }
        )

    @mock.patch('urllib3.PoolManager')
    def test_notification_config_id_key_is_optional(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                'PUT',
                'https://localhost:9000/my-test-bucket/?notification=',
                {
                    'Content-Md5': 'f+TfVp/A4pNnI7S4S+MkFg==',
                    'Content-Length': '196',
                    'User-Agent': _DEFAULT_USER_AGENT,
                },
                200, content=""
            )
        )
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_has_valid_event_names(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['object_created'],
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_filterspec_is_valid_1(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': []
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_filterspec_is_valid_2(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'S3Key': {
                            }
                        }
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_filterspec_is_valid_3(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                            }
                        }
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_filterspec_is_valid_4(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': []
                            }
                        }
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_filterspec_is_valid_5(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {
                                        'rule1': 'ab',
                                        'val1': 'abc'
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        )

    @raises(InvalidArgumentError)
    def test_notification_config_filterspec_is_valid_6(self):
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {
                                        'Name': 'ab',
                                        'Value': 'abc'
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        )

    @mock.patch('urllib3.PoolManager')
    def test_notification_config_filterspec_is_valid_7(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                'PUT',
                'https://localhost:9000/my-test-bucket/?notification=',
                {
                    'Content-Md5': 'k97dHBBUq9MR7ZViy7oUsw==',
                    'User-Agent': _DEFAULT_USER_AGENT,
                    'Content-Length': '300',
                },
                200, content=""
            )
        )
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {
                                        'Name': 'prefix',
                                        'Value': 'abc'
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        )

    @mock.patch('urllib3.PoolManager')
    def test_notification_config_filterspec_is_valid_8(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server
        mock_server.mock_add_request(
            MockResponse(
                'PUT',
                'https://localhost:9000/my-test-bucket/?notification=',
                {
                    'Content-Length': '300',
                    'Content-Md5': '2aIwAt1lAd5JShphHCD4GA==',
                    'User-Agent': _DEFAULT_USER_AGENT,
                },
                200, content=""
            )
        )
        client = Minio('localhost:9000')
        client.set_bucket_notification(
            'my-test-bucket',
            {
                'QueueConfigurations': [
                    {
                        'Id': '1',
                        'Arn': 'arn1',
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {
                                        'Name': 'suffix',
                                        'Value': 'abc'
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        )
