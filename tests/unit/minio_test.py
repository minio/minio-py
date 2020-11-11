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

from nose.tools import eq_, raises

from minio import Minio
from minio import __version__ as minio_version
from minio.api import _DEFAULT_USER_AGENT
from minio.helpers import BaseURL, check_bucket_name


class ValidBucketName(TestCase):
    @raises(ValueError)
    def test_bucket_name(self):
        check_bucket_name('bucketName=', False)

    @raises(ValueError)
    def test_bucket_name_invalid_characters(self):
        check_bucket_name('$$$bcuket', False)

    @raises(ValueError)
    def test_bucket_name_length(self):
        check_bucket_name('dd', False)

    @raises(ValueError)
    def test_bucket_name_periods(self):
        check_bucket_name('dd..mybucket', False)

    @raises(ValueError)
    def test_bucket_name_begins_period(self):
        check_bucket_name('.ddmybucket', False)


class GetURLTests(TestCase):
    def test_url_build(self):
        url = BaseURL('http://localhost:9000', None)
        eq_(
            urlunsplit(url.build("GET", None, bucket_name='bucket-name')),
            'http://localhost:9000/bucket-name',
        )
        eq_(
            urlunsplit(
                url.build("GET", None, bucket_name='bucket-name',
                          object_name='objectName'),
            ),
            'http://localhost:9000/bucket-name/objectName',
        )
        eq_(
            urlunsplit(
                url.build("GET", 'us-east-1', bucket_name='bucket-name',
                          object_name='objectName',
                          query_params={'foo': 'bar'}),
            ),
            'http://localhost:9000/bucket-name/objectName?foo=bar',
        )
        eq_(
            urlunsplit(
                url.build("GET", 'us-east-1', bucket_name='bucket-name',
                          object_name='objectName',
                          query_params={'foo': 'bar', 'b': 'c', 'a': 'b'}),
            ),
            'http://localhost:9000/bucket-name/objectName?a=b&b=c&foo=bar',
        )
        eq_(
            urlunsplit(
                url.build("GET", 'us-east-1', bucket_name='bucket-name',
                          object_name='path/to/objectName/'),
            ),
            'http://localhost:9000/bucket-name/path/to/objectName/',
        )

        # S3 urls.
        url = BaseURL('https://s3.amazonaws.com', None)
        eq_(
            urlunsplit(url.build("GET", "us-east-1")),
            'https://s3.us-east-1.amazonaws.com/',
        )
        eq_(
            urlunsplit(
                url.build("GET", "eu-west-1", bucket_name='my.bucket.name'),
            ),
            'https://s3.eu-west-1.amazonaws.com/my.bucket.name',
        )
        eq_(
            urlunsplit(
                url.build("GET", 'us-west-2', bucket_name='bucket-name',
                          object_name='objectName'),
            ),
            'https://bucket-name.s3.us-west-2.amazonaws.com/objectName',
        )
        eq_(
            urlunsplit(
                url.build("GET", "us-east-1", bucket_name='bucket-name',
                          object_name='objectName',
                          query_params={'versionId': 'uuid'}),
            ),
            "https://bucket-name.s3.us-east-1.amazonaws.com"
            "/objectName?versionId=uuid",
        )

    @raises(TypeError)
    def test_minio_requires_string(self):
        Minio(10)

    @raises(ValueError)
    def test_minio_requires_hostname(self):
        Minio('http://')


class UserAgentTests(TestCase):
    def test_default_user_agent(self):
        client = Minio('localhost')
        eq_(client._user_agent, _DEFAULT_USER_AGENT)

    def test_set_app_info(self):
        client = Minio('localhost')
        expected_user_agent = _DEFAULT_USER_AGENT + ' hello/' + minio_version
        client.set_app_info('hello', minio_version)
        eq_(client._user_agent, expected_user_agent)

    @raises(ValueError)
    def test_set_app_info_requires_non_empty_name(self):
        client = Minio('localhost:9000')
        client.set_app_info('', minio_version)

    @raises(ValueError)
    def test_set_app_info_requires_non_empty_version(self):
        client = Minio('localhost:9000')
        client.set_app_info('hello', '')


class GetRegionTests(TestCase):
    def test_region_none(self):
        region = BaseURL('http://localhost', None).region
        eq_(region, None)

    def test_region_us_west(self):
        region = BaseURL('https://s3-us-west-1.amazonaws.com', None).region
        eq_(region, None)

    def test_region_with_dot(self):
        region = BaseURL('https://s3.us-west-1.amazonaws.com', None).region
        eq_(region, 'us-west-1')

    def test_region_with_dualstack(self):
        region = BaseURL(
            'https://s3.dualstack.us-west-1.amazonaws.com', None,
        ).region
        eq_(region, 'us-west-1')

    def test_region_us_east(self):
        region = BaseURL('http://s3.amazonaws.com', None).region
        eq_(region, None)

    @raises(ValueError)
    def test_invalid_value(self):
        BaseURL(None, None)
