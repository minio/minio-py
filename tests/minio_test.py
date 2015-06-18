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

import platform
from unittest import TestCase

from nose.tools import *

from minio import minio


class GetUrlTests(TestCase):
    def test_get_target_url_works(self):
        client = minio.Minio('https://localhost:9000')
        eq_(client._get_target_url(), 'https://localhost:9000/')
        eq_(client._get_target_url(), 'https://localhost:9000/')
        eq_(client._get_target_url('bucket'), 'https://localhost:9000/bucket')
        eq_(client._get_target_url('bucket', 'key'), 'https://localhost:9000/bucket/key')
        eq_(client._get_target_url('bucket', 'key', None), 'https://localhost:9000/bucket/key')
        eq_(client._get_target_url('bucket', 'key', {'foo': 'bar'}), 'https://localhost:9000/bucket/key?foo=bar')
        eq_(client._get_target_url('bucket', 'key', {'foo': 'bar', 'b': 'c', 'a': 'b'}),
            'https://localhost:9000/bucket/key?a=b&b=c&foo=bar')
        client2 = minio.Minio('http://play.minio.io')
        eq_(client2._get_target_url(), 'http://play.minio.io/')

    @raises(TypeError)
    def test_minio_requires_string(self):
        minio.Minio(10)

    @raises(ValueError)
    def test_minio_requires_scheme(self):
        minio.Minio('play.minio.io')

    @raises(ValueError)
    def test_minio_requires_netloc(self):
        minio.Minio('http://')


class UserAgentTests(TestCase):
    def test_default_user_agent(self):
        client = minio.Minio('http://localhost')
        eq_(client._user_agent, 'minio-py/0.0.1 (' + platform.system() + '; ' + platform.machine() + ')')

    def test_add_user_agent(self):
        client = minio.Minio('http://localhost')

        expected_user_agent = 'minio-py/0.0.1 (' + platform.system() + '; ' + platform.machine() + ')'
        expected_user_agent += ' hello/1.0.0 (World; Edition)'

        client.add_user_agent('hello', '1.0.0', ['World', 'Edition'])
        eq_(client._user_agent, expected_user_agent)

    @raises(TypeError)
    def test_add_user_agent_requires_string_name(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent(10, '1.0.0', ['World', 'Edition'])

    @raises(ValueError)
    def test_add_user_agent_requires_non_empty_name(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent('', '1.0.0', ['World', 'Edition'])

    @raises(TypeError)
    def test_add_user_agent_requires_version(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent('hello', 10, ['World', 'Edition'])

    @raises(ValueError)
    def test_add_user_agent_requires_non_empty_version(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent('hello', '', ['World', 'Edition'])

    @raises(TypeError)
    def test_add_user_agent_parameter(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent('hello', '1.0.0', ['World', 10])

    @raises(TypeError)
    def test_parameter_must_be_string(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent('hello', '1.0.0', ['World', 10])

    @raises(ValueError)
    def test_parameter_must_not_be_empty(self):
        client = minio.Minio('http://localhost')
        client.add_user_agent('hello', '1.0.0', ['World', ''])

class MakeBucket(TestCase):
    def test_make_bucket_works(self):
        client = minio.Minio('http://localhost:9000')
        client.make_bucket('hello')
        foo()

## add test for this:
# eq_(client._get_client(None, 'key'), 'https://localhost:9000/') # should raise
