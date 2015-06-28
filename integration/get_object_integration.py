# Minimal Object Storage Library, (C) 2015 Minio, Inc.
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

from .credentials import Credentials
from minio import minio
from minio.parsers import ResponseError

__author__ = 'minio'

credentials = Credentials()

url = credentials.url()
access_key = credentials.access_key()
secret_key = credentials.secret_key()

client = minio.Minio(url, access_key=access_key, secret_key=secret_key)

bucket = 'goroutine-py'


class GetObjectIntegration(TestCase):
    def get_object_test(self):
        data = client.get_object(bucket, 'hello/world')
        collected_data = []
        for d in data:
            collected_data.append(d)
        print ''.join(collected_data)

    def get_object_in_dir_test(self):
        data = client.get_object(bucket, 'hello/world')
        collected_data = []
        for d in data:
            collected_data.append(d)
        print ''.join(collected_data)

    @raises(ResponseError)
    def get_nonexistent_object_test(self):
        client.get_object(bucket, 'foo')

    @raises(ResponseError)
    def get_from_unknown_bucket_test(self):
        client.get_object('goroutine-no-exist', 'hello')
