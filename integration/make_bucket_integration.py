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

from minio import minio
from minio.exceptions import BucketExistsException, InvalidBucketNameException

__author__ = 'minio'

server = 'https://s3-us-west-2.amazonaws.com'
bucket = 'goroutine-py'

access_key = None
secret_key = None

client = minio.Minio(server, access_key=access_key, secret_key=secret_key)


class MakeBucketIntegrationTests(TestCase):
    def test_make_bucket_works(self):
        client.make_bucket(bucket)

    @raises(BucketExistsException)
    def test_make_existing_bucket_fails(self):
        client.make_bucket(bucket)

    @raises(InvalidBucketNameException)
    def test_invalid_bucket_name_exception(self):
        client.make_bucket('1234')
