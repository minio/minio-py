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

import unittest.mock as mock
from unittest import TestCase

from minio import Minio
from minio.api import _DEFAULT_USER_AGENT
from minio.error import S3Error

from .helpers import generate_error
from .minio_mocks import MockConnection, MockResponse


class RemoveBuckets(TestCase):
    def test_bucket_names_is_list_or_tuple(self):
        client = Minio('localhost:9000')
        # Test with string instead of list
        self.assertRaises(ValueError, client.remove_buckets, "bucket1")
        # Test with integer
        self.assertRaises(ValueError, client.remove_buckets, 1234)

    def test_bucket_names_is_not_empty(self):
        client = Minio('localhost:9000')
        self.assertRaises(ValueError, client.remove_buckets, [])

    def test_invalid_bucket_names_in_list(self):
        client = Minio('localhost:9000')
        # Test with non-string bucket names
        self.assertRaises(TypeError, client.remove_buckets, [1234, "valid-bucket"])
        # Test with invalid bucket name format
        self.assertRaises(ValueError, client.remove_buckets, ["AB*CD", "valid-bucket"])

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_all_success(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        # Mock successful responses for each bucket
        bucket_names = ['bucket1', 'bucket2', 'bucket3']
        for bucket_name in bucket_names:
            mock_server.mock_add_request(
                MockResponse('DELETE',
                             f'https://localhost:9000/{bucket_name}',
                             {'User-Agent': _DEFAULT_USER_AGENT},
                             204)
            )

        client = Minio('localhost:9000')
        results = client.remove_buckets(bucket_names)

        # All buckets should be removed successfully
        for bucket_name in bucket_names:
            self.assertTrue(results[bucket_name])

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_with_failure_fail_on_error_true(self, mock_connection):
        error_xml = generate_error('NoSuchBucket', 'The specified bucket does not exist',
                                   'request_id', 'host_id', 'resource', 'bucket2', 'object')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        # First bucket succeeds
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket1',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         204)
        )

        # Second bucket fails (doesn't exist)
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket2',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         404,
                         response_headers={"Content-Type": "application/xml"},
                         content=error_xml.encode())
        )

        client = Minio('localhost:9000')
        # Should raise S3Error on first failure when fail_on_error=True (default)
        self.assertRaises(S3Error, client.remove_buckets, ['bucket1', 'bucket2', 'bucket3'])

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_with_failure_fail_on_error_false(self, mock_connection):
        error_xml = generate_error('NoSuchBucket', 'The specified bucket does not exist',
                                   'request_id', 'host_id', 'resource', 'bucket2', 'object')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        bucket_names = ['bucket1', 'bucket2', 'bucket3']

        # First bucket succeeds
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket1',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         204)
        )

        # Second bucket fails (doesn't exist)
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket2',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         404,
                         response_headers={"Content-Type": "application/xml"},
                         content=error_xml.encode())
        )

        # Third bucket succeeds
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket3',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         204)
        )

        client = Minio('localhost:9000')
        results = client.remove_buckets(bucket_names, fail_on_error=False)

        # Check results
        self.assertTrue(results['bucket1'])  # Success
        self.assertIsInstance(results['bucket2'], S3Error)  # Failed with S3Error
        self.assertTrue(results['bucket3'])  # Success

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_bucket_not_empty_error(self, mock_connection):
        error_xml = generate_error('BucketNotEmpty', 'The bucket you tried to delete is not empty',
                                   'request_id', 'host_id', 'resource', 'bucket1', 'object')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        # Bucket fails because it's not empty
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket1',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         409,
                         response_headers={"Content-Type": "application/xml"},
                         content=error_xml.encode())
        )

        client = Minio('localhost:9000')
        results = client.remove_buckets(['bucket1'], fail_on_error=False)

        # Check that the error is properly captured
        self.assertIsInstance(results['bucket1'], S3Error)
        self.assertEqual(results['bucket1'].code, 'BucketNotEmpty')

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_mixed_errors(self, mock_connection):
        no_such_bucket_xml = generate_error('NoSuchBucket', 'The specified bucket does not exist',
                                            'request_id1', 'host_id1', 'resource1', 'bucket2', 'object')
        bucket_not_empty_xml = generate_error('BucketNotEmpty', 'The bucket you tried to delete is not empty',
                                              'request_id2', 'host_id2', 'resource2', 'bucket3', 'object')

        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        bucket_names = ['bucket1', 'bucket2', 'bucket3', 'bucket4']

        # First bucket succeeds
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket1',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         204)
        )

        # Second bucket fails - doesn't exist
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket2',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         404,
                         response_headers={"Content-Type": "application/xml"},
                         content=no_such_bucket_xml.encode())
        )

        # Third bucket fails - not empty
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket3',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         409,
                         response_headers={"Content-Type": "application/xml"},
                         content=bucket_not_empty_xml.encode())
        )

        # Fourth bucket succeeds
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket4',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         204)
        )

        client = Minio('localhost:9000')
        results = client.remove_buckets(bucket_names, fail_on_error=False)

        # Check mixed results
        self.assertTrue(results['bucket1'])  # Success
        self.assertIsInstance(results['bucket2'], S3Error)  # NoSuchBucket error
        self.assertEqual(results['bucket2'].code, 'NoSuchBucket')
        self.assertIsInstance(results['bucket3'], S3Error)  # BucketNotEmpty error
        self.assertEqual(results['bucket3'].code, 'BucketNotEmpty')
        self.assertTrue(results['bucket4'])  # Success

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_access_denied_error(self, mock_connection):
        error_xml = generate_error('AccessDenied', 'Access Denied',
                                   'request_id', 'host_id', 'resource', 'bucket1', 'object')
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        # Bucket fails due to access denied
        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/bucket1',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         403,
                         response_headers={"Content-Type": "application/xml"},
                         content=error_xml.encode())
        )

        client = Minio('localhost:9000')
        results = client.remove_buckets(['bucket1'], fail_on_error=False)

        # Check that the access denied error is properly captured
        self.assertIsInstance(results['bucket1'], S3Error)
        self.assertEqual(results['bucket1'].code, 'AccessDenied')

    @mock.patch('urllib3.PoolManager')
    def test_remove_buckets_single_bucket_success(self, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        mock_server.mock_add_request(
            MockResponse('DELETE',
                         'https://localhost:9000/single-bucket',
                         {'User-Agent': _DEFAULT_USER_AGENT},
                         204)
        )

        client = Minio('localhost:9000')
        results = client.remove_buckets(['single-bucket'])

        # Single bucket should be removed successfully
        self.assertTrue(results['single-bucket'])
        self.assertEqual(len(results), 1)