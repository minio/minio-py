# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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
import platform
from unittest import TestCase

from nose.tools import *

from minio import Minio, __version__
from minio.error import InvalidEndpointError
from minio.helpers import get_target_url

class GetURLTests(TestCase):
    def test_get_target_url_works(self):
        url = 'http://localhost:9000'
        eq_(get_target_url(url, 'bucketName'),
            'http://localhost:9000/bucketName/')
        eq_(get_target_url(url, 'bucketName', 'objectName'),
            'http://localhost:9000/bucketName/objectName')
        eq_(get_target_url(url, 'bucketName', 'objectName', None),
            'http://localhost:9000/bucketName/objectName')
        eq_(get_target_url(url, 'bucketName', 'objectName', {'foo': 'bar'}),
            'http://localhost:9000/bucketName/objectName?foo=bar')
        eq_(get_target_url(url, 'bucketName', 'objectName',
                           {'foo': 'bar',
                            'b': 'c',
                            'a': 'b'}),
            'http://localhost:9000/bucketName/objectName?a=b&b=c&foo=bar')
        s3_url = 'https://s3.amazonaws.com'
        eq_(get_target_url(s3_url), 'https://s3.amazonaws.com/')

    @raises(TypeError)
    def test_minio_requires_string(self):
        Minio(10)

    @raises(InvalidEndpointError)
    def test_minio_requires_scheme(self):
        Minio('play.minio.io')

    @raises(InvalidEndpointError)
    def test_minio_requires_netloc(self):
        Minio('http://')


class UserAgentTests(TestCase):
    def test_default_user_agent(self):
        client = Minio('http://localhost')
        eq_(client._user_agent, 'minio-py/' + __version__ + ' (' + \
            platform.system() + \
            '; ' + platform.machine() + ')')

    def test_set_app_info(self):
        client = Minio('http://localhost')        
        expected_user_agent = 'minio-py/' + __version__  + ' (' + \
            platform.system() + '; ' + \
            platform.machine() + ')'
        
        expected_user_agent += ' hello/1.0.0 (World; Edition)'

        client.set_app_info('hello', '1.0.0', ['World', 'Edition'])
        eq_(client._user_agent, expected_user_agent)

    @raises(TypeError)
    def test_set_app_info_requires_string_name(self):
        client = Minio('http://localhost:9000')
        client.set_app_info(10, '1.0.0', ['World', 'Edition'])

    @raises(ValueError)
    def test_set_app_info_requires_non_empty_name(self):
        client = Minio('http://localhost:9000')
        client.set_app_info('', '1.0.0', ['World', 'Edition'])

    @raises(TypeError)
    def test_set_app_info_requires_version(self):
        client = Minio('http://localhost:9000')
        client.set_app_info('hello', 10, ['World', 'Edition'])

    @raises(ValueError)
    def test_set_app_info_requires_non_empty_version(self):
        client = Minio('http://localhost:9000')
        client.set_app_info('hello', '', ['World', 'Edition'])
