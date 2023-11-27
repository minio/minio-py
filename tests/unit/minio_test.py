# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016, 2017 MinIO, Inc.
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
from urllib.parse import urlunsplit

from minio import Minio
from minio import __version__ as minio_version
from minio.api import _DEFAULT_USER_AGENT
from minio.helpers import BaseURL, check_bucket_name


class ValidBucketName(TestCase):
    def test_bucket_name(self):
        self.assertRaises(ValueError, check_bucket_name, 'bucketName=', False)

    def test_bucket_name_invalid_characters(self):
        self.assertRaises(ValueError, check_bucket_name, '$$$bcuket', False)

    def test_bucket_name_length(self):
        self.assertRaises(ValueError, check_bucket_name, 'dd', False)

    def test_bucket_name_periods(self):
        self.assertRaises(ValueError, check_bucket_name, 'dd..mybucket', False)

    def test_bucket_name_begins_period(self):
        self.assertRaises(ValueError, check_bucket_name, '.ddmybucket', False)


class GetURLTests(TestCase):
    def test_url_build(self):
        url = BaseURL('http://localhost:9000', None)
        self.assertEqual(
            urlunsplit(url.build("GET", None, bucket_name='bucket-name')),
            'http://localhost:9000/bucket-name',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", None, bucket_name='bucket-name',
                          object_name='objectName'),
            ),
            'http://localhost:9000/bucket-name/objectName',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", 'us-east-1', bucket_name='bucket-name',
                          object_name='objectName',
                          query_params={'foo': 'bar'}),
            ),
            'http://localhost:9000/bucket-name/objectName?foo=bar',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", 'us-east-1', bucket_name='bucket-name',
                          object_name='objectName',
                          query_params={'foo': 'bar', 'b': 'c', 'a': 'b'}),
            ),
            'http://localhost:9000/bucket-name/objectName?a=b&b=c&foo=bar',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", 'us-east-1', bucket_name='bucket-name',
                          object_name='path/to/objectName/'),
            ),
            'http://localhost:9000/bucket-name/path/to/objectName/',
        )

        # S3 urls.
        url = BaseURL('https://s3.amazonaws.com', None)
        self.assertEqual(
            urlunsplit(url.build("GET", "us-east-1")),
            'https://s3.us-east-1.amazonaws.com/',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", "eu-west-1", bucket_name='my.bucket.name'),
            ),
            'https://s3.eu-west-1.amazonaws.com/my.bucket.name',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", 'us-west-2', bucket_name='bucket-name',
                          object_name='objectName'),
            ),
            'https://bucket-name.s3.us-west-2.amazonaws.com/objectName',
        )
        self.assertEqual(
            urlunsplit(
                url.build("GET", "us-east-1", bucket_name='bucket-name',
                          object_name='objectName',
                          query_params={'versionId': 'uuid'}),
            ),
            "https://bucket-name.s3.us-east-1.amazonaws.com"
            "/objectName?versionId=uuid",
        )

    def test_minio_requires_string(self):
        self.assertRaises(TypeError, Minio, 10)

    def test_minio_requires_hostname(self):
        self.assertRaises(ValueError, Minio, 'http://')


class UserAgentTests(TestCase):
    def test_default_user_agent(self):
        client = Minio('localhost')
        self.assertEqual(client._user_agent, _DEFAULT_USER_AGENT)

    def test_set_app_info(self):
        client = Minio('localhost')
        expected_user_agent = _DEFAULT_USER_AGENT + ' hello/' + minio_version
        client.set_app_info('hello', minio_version)
        self.assertEqual(client._user_agent, expected_user_agent)

    def test_set_app_info_requires_non_empty_name(self):
        client = Minio('localhost:9000')
        self.assertRaises(ValueError, client.set_app_info, '', minio_version)

    def test_set_app_info_requires_non_empty_version(self):
        client = Minio('localhost:9000')
        self.assertRaises(ValueError, client.set_app_info, 'hello', '')


class GetRegionTests(TestCase):
    def test_region_none(self):
        region = BaseURL('http://localhost', None).region
        self.assertIsNone(region)

    def test_region_us_west(self):
        region = BaseURL('https://s3-us-west-1.amazonaws.com', None).region
        self.assertEqual(region, "")

    def test_region_with_dot(self):
        region = BaseURL('https://s3.us-west-1.amazonaws.com', None).region
        self.assertEqual(region, 'us-west-1')

    def test_region_with_dualstack(self):
        region = BaseURL(
            'https://s3.dualstack.us-west-1.amazonaws.com', None,
        ).region
        self.assertEqual(region, 'us-west-1')

    def test_region_us_east(self):
        region = BaseURL('http://s3.amazonaws.com', None).region
        self.assertEqual(region, "")

    def test_invalid_value(self):
        self.assertRaises(ValueError, BaseURL, None, None)
