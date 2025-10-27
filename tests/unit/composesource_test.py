# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 MinIO, Inc.
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
from unittest import TestCase

from minio.commonconfig import ComposeSource
from minio.error import MinioException


class ComposeSourceTest(TestCase):
    def test_object_size(self):
        source = ComposeSource(bucket_name="my-bucket",
                               object_name="my-object")
        with self.assertRaises(MinioException) as exc:
            _ = source.object_size

        msg = "build_headers() must be called prior to this method invocation"
        self.assertEqual(msg, str(exc.exception))
