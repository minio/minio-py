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

from nose.tools import raises, eq_

from minio import Minio
from minio import __version__ as minio_version
from minio.api import _DEFAULT_USER_AGENT
from minio.error import InvalidEndpointError, InvalidBucketError
from minio.helpers import (get_target_url, is_valid_bucket_name,
                           get_s3_region_from_endpoint)

class ValidBucketName(TestCase):
    @raises(InvalidBucketError)
    def test_bucket_name(self):
        is_valid_bucket_name('bucketName')

    @raises(InvalidBucketError)
    def test_bucket_name_invalid_characters(self):
        is_valid_bucket_name('$$$bcuket')

    @raises(InvalidBucketError)
    def test_bucket_name_length(self):
        is_valid_bucket_name('dd')

    @raises(InvalidBucketError)
    def test_bucket_name_periods(self):
        is_valid_bucket_name('dd..mybucket')

    @raises(InvalidBucketError)
    def test_bucket_name_begins_period(self):
        is_valid_bucket_name('.ddmybucket')

class GetURLTests(TestCase):
    def test_get_target_url_works(self):
        url = 'http://localhost:9000'
        eq_(get_target_url(url, 'bucket-name'),
            'http://localhost:9000/bucket-name/')
        eq_(get_target_url(url, 'bucket-name', 'objectName'),
            'http://localhost:9000/bucket-name/objectName')
        eq_(get_target_url(url, 'bucket-name', 'objectName', None),
            'http://localhost:9000/bucket-name/objectName')
        eq_(get_target_url(url, 'bucket-name', 'objectName', 'us-east-1',
                           {'foo': 'bar'}),
            'http://localhost:9000/bucket-name/objectName?foo=bar')
        eq_(get_target_url(url, 'bucket-name', 'objectName', 'us-east-1',
                           {'foo': 'bar',
                            'b': 'c',
                            'a': 'b'}),
            'http://localhost:9000/bucket-name/objectName?a=b&b=c&foo=bar')
        # S3 urls.
        s3_url = 'https://s3.amazonaws.com'
        eq_(get_target_url(s3_url), 'https://s3.amazonaws.com/')
        eq_(get_target_url(s3_url, 'my.bucket.name'),
            'https://s3.amazonaws.com/my.bucket.name/')
        eq_(get_target_url(s3_url,
                           'bucket-name',
                           'objectName',
                           'us-west-2', None),
            'https://bucket-name.s3-us-west-2.amazonaws.com/objectName')

    @raises(TypeError)
    def test_minio_requires_string(self):
        Minio(10)

    @raises(InvalidEndpointError)
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
        region = get_s3_region_from_endpoint('localhost')
        eq_(region, None)

    def test_region_us_west(self):
        region = get_s3_region_from_endpoint('s3-us-west-1.amazonaws.com')
        eq_(region, 'us-west-1')

    def test_region_with_dot(self):
        region = get_s3_region_from_endpoint('s3.us-west-1.amazonaws.com')
        eq_(region, 'us-west-1')

    def test_region_with_dualstack(self):
        region = get_s3_region_from_endpoint('s3.dualstack.us-west-1.amazonaws.com')
        eq_(region, 'us-west-1')

    def test_region_us_east(self):
        region = get_s3_region_from_endpoint('s3.amazonaws.com')
        eq_(region, None)

    @raises(TypeError)
    def test_invalid_value(self):
        region = get_s3_region_from_endpoint(None)
