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

from unittest import TestCase

from minio import Minio


class PutObjectTest(TestCase):
    def test_object_is_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(TypeError):
            client.put_object(
                bucket_name='hello',
                object_name=1234,
                data=1,
                length=iter([1, 2, 3]),
            )

    def test_object_is_not_empty_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.put_object(
                bucket_name='hello',
                object_name=' \t \n ',
                data=1,
                length=iter([1, 2, 3]),
            )

    def test_length_is_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(TypeError):
            client.put_object(
                bucket_name='hello',
                object_name=1234,
                data='1',
                length=iter([1, 2, 3]),
            )

    def test_length_is_not_empty_string(self):
        client = Minio(endpoint='localhost:9000')
        with self.assertRaises(ValueError):
            client.put_object(
                bucket_name='hello',
                object_name=' \t \n ',
                data=-1,
                length=iter([1, 2, 3]),
            )
