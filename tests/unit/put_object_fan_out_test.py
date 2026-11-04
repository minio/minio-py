# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
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

import io
import unittest
from datetime import datetime, timezone

from urllib3.response import HTTPResponse

from minio.models import PutObjectFanOutResponse
from minio.time import from_iso8601utc


class PutObjectFanOutResponseTest(unittest.TestCase):
    def test_nanosecond_last_modified(self) -> None:
        # MinIO encodes lastModified with Go's RFC3339Nano layout.
        body = (
            b'{"key":"a","etag":"e1",'
            b'"lastModified":"2025-01-07T09:57:45.204541019Z"}\n'
            b'{"key":"b","etag":"e2",'
            b'"lastModified":"2025-01-07T09:57:45.2Z"}\n'
        )
        response = PutObjectFanOutResponse(
            response=HTTPResponse(
                body=io.BytesIO(body), preload_content=False,
            ),
            bucket_name="bucket",
            region="us-east-1",
        )
        self.assertEqual(
            [result.last_modified for result in response.results],
            [
                datetime(2025, 1, 7, 9, 57, 45, 204541, tzinfo=timezone.utc),
                datetime(2025, 1, 7, 9, 57, 45, 200000, tzinfo=timezone.utc),
            ],
        )

    def test_malformed_fraction_raises(self) -> None:
        with self.assertRaises(ValueError):
            from_iso8601utc("2025-01-07T09:57:45.123456oopsZ")
