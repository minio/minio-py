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
import io
import os
from unittest import TestCase

from .credentials import Credentials
from minio import minio

__author__ = 'minio'

credentials = Credentials()

url = credentials.url()
access_key = credentials.access_key()
secret_key = credentials.secret_key()

client = minio.Minio(url, access_key=access_key, secret_key=secret_key)

bucket = 'goroutine-py'


class PutObjectIntegration(TestCase):
    def put_small_object_test(self):
        client.put_object(bucket, 'small_obj', 11, 'hello world', content_type='text/plain')

    def put_small_file_test(self):
        file_stat = os.stat('CONTRIBUTING.md')
        with open('CONTRIBUTING.md', 'rb') as data_file:
            client.put_object(bucket, 'small_obj2', file_stat.st_size, data_file, content_type='text/plain')

    def put_large_object_test(self):
        a = []
        for i in range(0, 11 * 1024 * 1024):
            a.append('a')
        a = ''.join(a)
        client.put_object(bucket, 'large_obj', 11 * 1024 * 1024, a, content_type='text/plain')

    def put_large_file_test(self):
        file_name = '11mb'
        file_stat = os.stat(file_name)
        with open(file_name, 'rb') as data_file:
            client.put_object(bucket, 'large_obj2', file_stat.st_size, data_file)

    def put_large_file_with_resume_test(self):
        file_name = '11mb'
        file_stat = os.stat(file_name)
        with open(file_name, 'rb') as data_file:
            try:
                client.put_object(bucket, 'large_obj3', file_stat.st_size - (2 * 1024 * 1024), data_file)
            except ValueError:
                pass

        with open(file_name, 'rb') as data_file:
            client.put_object(bucket, 'large_obj3', file_stat.st_size, data_file)

    def put_binary_object_test(self):
        file_name = '/bin/ls'
        file_stat = os.stat(file_name)
        with io.open(file_name, 'rb') as data_file:
            client.put_object(bucket, 'binary_object', file_stat.st_size, data_file)
