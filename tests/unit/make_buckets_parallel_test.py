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
from minio.datatypes import BaseHTTPResponse

from .helpers import generate_error
from .minio_mocks import MockConnection, MockResponse


class MakeBucketsParallel(TestCase):
    def test_bucket_names_is_list_or_tuple(self):
        client = Minio('localhost:9000')
        # Test with string instead of list
        self.assertRaises(ValueError, client.make_buckets, "bucket1")
        # Test with integer
        self.assertRaises(ValueError, client.make_buckets, 1234)

    def test_bucket_names_is_not_empty(self):
        client = Minio('localhost:9000')
        self.assertRaises(ValueError, client.make_buckets, [])

    def test_invalid_bucket_names_in_list(self):
        client = Minio('localhost:9000')
        # Test with non-string bucket names
        self.assertRaises(TypeError, client.make_buckets, [1234, "valid-bucket"])

    @mock.patch('urllib3.PoolManager')
    @mock.patch('concurrent.futures.ThreadPoolExecutor')
    def test_make_buckets_parallel_all_success(self, mock_executor, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        # Mock the ThreadPoolExecutor
        mock_executor_instance = mock.MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance

        bucket_names = ['bucket1', 'bucket2', 'bucket3']

        # Mock successful responses for each bucket
        for bucket_name in bucket_names:
            mock_server.mock_add_request(
                MockResponse('PUT',
                             f'https://localhost:9000/{bucket_name}',
                             {'User-Agent': _DEFAULT_USER_AGENT},
                             200)
            )

        # Mock futures and their results
        mock_futures = []
        for bucket_name in bucket_names:
            mock_future = mock.MagicMock()
            mock_future.result.return_value = (bucket_name, True)
            mock_futures.append(mock_future)

        mock_executor_instance.submit.side_effect = mock_futures

        # Mock as_completed to return futures in order
        with mock.patch('concurrent.futures.as_completed', return_value=mock_futures):
            client = Minio('localhost:9000')
            results = client.make_buckets_parallel(bucket_names)

        # All buckets should be created successfully
        for bucket_name in bucket_names:
            self.assertTrue(results[bucket_name])

    @mock.patch('urllib3.PoolManager')
    @mock.patch('concurrent.futures.ThreadPoolExecutor')
    def test_make_buckets_parallel_mixed_results(self, mock_executor, mock_connection):
        mock_server = MockConnection()
        mock_connection.return_value = mock_server

        # Mock the ThreadPoolExecutor
        mock_executor_instance = mock.MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance

        bucket_names = ['bucket1', 'bucket2', 'bucket3']

        # Mock responses
        mock_server.mock_add_request(
            MockResponse('PUT', 'https://localhost:9000/bucket1',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200)
        )

        error_xml = generate_error('BucketAlreadyExists', 'Bucket already exists',
                                   'request_id', 'host_id', 'resource', 'bucket2', 'object')
        mock_server.mock_add_request(
            MockResponse('PUT', 'https://localhost:9000/bucket2',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 409,
                         response_headers={"Content-Type": "application/xml"},
                         content=error_xml.encode())
        )

        mock_server.mock_add_request(
            MockResponse('PUT', 'https://localhost:9000/bucket3',
                         {'User-Agent': _DEFAULT_USER_AGENT}, 200)
        )

        # Mock futures with mixed results
        mock_future1 = mock.MagicMock()
        mock_future1.result.return_value = ('bucket1', True)

        # Mock BaseHTTPResponse
        mock_response = mock.MagicMock(spec=BaseHTTPResponse)
        mock_response.status = 409
        mock_response.reason = "Conflict"
        mock_response.headers = {"Content-Type": "application/xml"}

        mock_future2 = mock.MagicMock()
        mock_future2.result.return_value = ('bucket2', S3Error(
            response=mock_response,
            code="BucketAlreadyExists",
            message="Bucket already exists",
            resource="/bucket2",
            request_id="request_id",
            host_id="host_id",
            bucket_name="bucket2",
            object_name=None,
        ))


        mock_future3 = mock.MagicMock()
        mock_future3.result.return_value = ('bucket3', True)

        mock_futures = [mock_future1, mock_future2, mock_future3]
        mock_executor_instance.submit.side_effect = mock_futures

        with mock.patch('concurrent.futures.as_completed', return_value=mock_futures):
            client = Minio('localhost:9000')
            results = client.make_buckets_parallel(bucket_names)

        # Check mixed results
        self.assertTrue(results['bucket1'])
        self.assertIsInstance(results['bucket2'], S3Error)
        self.assertTrue(results['bucket3'])

    def test_make_buckets_parallel_custom_max_workers(self):
        client = Minio('localhost:9000')

        with mock.patch('concurrent.futures.ThreadPoolExecutor') as mock_executor:
            mock_executor_instance = mock.MagicMock()
            mock_executor.return_value.__enter__.return_value = mock_executor_instance
            mock_executor_instance.submit.return_value.result.return_value = ('bucket1', True)

            with mock.patch('concurrent.futures.as_completed',
                            return_value=[mock_executor_instance.submit.return_value]):
                client.make_buckets_parallel(['bucket1'], max_workers=10)

            # Verify ThreadPoolExecutor was called with custom max_workers
            mock_executor.assert_called_with(max_workers=10)