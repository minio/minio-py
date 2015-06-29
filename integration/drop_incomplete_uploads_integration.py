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

from .credentials import Credentials
from minio import minio

__author__ = 'minio'

credentials = Credentials()

url = credentials.url()
access_key = credentials.access_key()
secret_key = credentials.secret_key()

client = minio.Minio(url, access_key=access_key, secret_key=secret_key)

bucket = 'goroutine-py'


class DropIncompleteUploadsIntegration(TestCase):
    # def put_large_file_test(self):
    #     file_name = '11mb'
    #     file_stat = os.stat(file_name)
    #     with open(file_name, 'rb') as data_file:
    #         try:
    #             client.put_object(bucket, 'incomplete-1', file_stat.st_size - (2 * 1024 * 1024), data_file)
    #         except ValueError:
    #             pass
    #
    #     with open(file_name, 'rb') as data_file:
    #         try:
    #             client.put_object(bucket, 'incomplete-2', file_stat.st_size - (2 * 1024 * 1024), data_file)
    #         except ValueError:
    #             pass

    # def drop_incomplete_uploads_test(self):
    #     client.drop_incomplete_upload(bucket, 'incomplete-1')

    def drop_incomplete_uploads_test(self):
        client.drop_all_incomplete_uploads(bucket)
