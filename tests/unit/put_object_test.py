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

from unittest import TestCase
from nose.tools import raises
from mock import MagicMock
from io import BytesIO

from minio import Minio

class PutObjectTest(TestCase):
    @raises(TypeError)
    def test_object_is_string(self):
        client = Minio('localhost:9000')
        client.put_object('hello', 1234, 1, iter([1, 2, 3]))

    @raises(ValueError)
    def test_object_is_not_empty_string(self):
        client = Minio('localhost:9000')
        client.put_object('hello', ' \t \n ', 1, iter([1, 2, 3]))

    @raises(TypeError)
    def test_length_is_string(self):
        client = Minio('localhost:9000')
        client.put_object('hello', 1234, '1', iter([1, 2, 3]))

    @raises(ValueError)
    def test_length_is_not_empty_string(self):
        client = Minio('localhost:9000')
        client.put_object('hello', ' \t \n ', -1, iter([1, 2, 3]))

    def test_put_without_length(self):
        client = Minio('localhost:9000')
        mock_do_put_object = MagicMock()
        client._do_put_object = mock_do_put_object
        mock_stream_put_object = MagicMock()
        client._stream_put_object = mock_stream_put_object

        part_size = 5*1024*1024
        content = b'b'*part_size
        bucket_name = 'hello'
        object_name = 'world'
        testfile = BytesIO(content)
        client.put_object(
            bucket_name,
            object_name,
            testfile,
            part_size=part_size,
        )

        mock_do_put_object.assert_called_once_with(
            bucket_name,
            object_name,
            content,
            part_size,
            metadata={'Content-Type': 'application/octet-stream'},
            sse=None,
            progress=None,
        )

    def test_put_without_length_stream(self):
        client = Minio('localhost:9000')
        mock_do_put_object = MagicMock()
        client._do_put_object = mock_do_put_object
        mock_stream_put_object = MagicMock()
        client._stream_put_object = mock_stream_put_object

        part_size = 5*1024*1024
        content = b"b"*(part_size+1)
        bucket_name = "hello"
        object_name = "world"
        testfile = BytesIO(content)
        client.put_object(
            bucket_name,
            object_name,
            testfile,
            part_size=part_size,
        )

        mock_stream_put_object.assert_called_once()
