# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 compatible cloud storage, (C) 2015 Minio, Inc.
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

from minio import minio, get_version
from minio.error import InvalidURLError
from minio.helpers import get_target_url


class GetUrlTests(TestCase):
    def test_get_target_url_works(self):
        url = 'http://localhost:9000'
        eq_(get_target_url(url, 'bucket'),
            'http://localhost:9000/bucket')
        eq_(get_target_url(url, 'bucket', 'key'),
            'http://localhost:9000/bucket/key')
        eq_(get_target_url(url, 'bucket', 'key', None),
            'http://localhost:9000/bucket/key')
        eq_(get_target_url(url, 'bucket', 'key', {'foo': 'bar'}),
            'http://localhost:9000/bucket/key?foo=bar')
        eq_(get_target_url(url, 'bucket', 'key',
                           {'foo': 'bar',
                            'b': 'c',
                            'a': 'b'}),
            'http://localhost:9000/bucket/key?a=b&b=c&foo=bar')
        s3_url = 'https://s3.amazonaws.com'
        eq_(get_target_url(s3_url), 'https://s3.amazonaws.com/')

    @raises(TypeError)
    def test_minio_requires_string(self):
        minio.Minio(10)

    @raises(InvalidURLError)
    def test_minio_requires_scheme(self):
        minio.Minio('play.minio.io')

    @raises(InvalidURLError)
    def test_minio_requires_netloc(self):
        minio.Minio('http://')


class UserAgentTests(TestCase):
    def test_default_user_agent(self):
        client = minio.Minio('http://localhost')
        eq_(client._user_agent, 'minio-py/' + get_version()+ ' (' + \
            platform.system() + \
            '; ' + platform.machine() + ')')

    def test_set_user_agent(self):
        client = minio.Minio('http://localhost')

        expected_user_agent = 'minio-py/' + get_version() + ' (' + \
            platform.system() + '; ' + \
            platform.machine() + ')'
        expected_user_agent += ' hello/1.0.0 (World; Edition)'

        client.set_user_agent('hello', '1.0.0', ['World', 'Edition'])
        eq_(client._user_agent, expected_user_agent)

    @raises(TypeError)
    def test_set_user_agent_requires_string_name(self):
        client = minio.Minio('http://localhost:9000')
        client.set_user_agent(10, '1.0.0', ['World', 'Edition'])

    @raises(ValueError)
    def test_set_user_agent_requires_non_empty_name(self):
        client = minio.Minio('http://localhost:9000')
        client.set_user_agent('', '1.0.0', ['World', 'Edition'])

    @raises(TypeError)
    def test_set_user_agent_requires_version(self):
        client = minio.Minio('http://localhost:9000')
        client.set_user_agent('hello', 10, ['World', 'Edition'])

    @raises(ValueError)
    def test_set_user_agent_requires_non_empty_version(self):
        client = minio.Minio('http://localhost:9000')
        client.set_user_agent('hello', '', ['World', 'Edition'])
