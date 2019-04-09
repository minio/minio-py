# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 MinIO, Inc.
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
from nose.tools import eq_
from minio.helpers import get_s3_endpoint, is_valid_endpoint

class GetS3Endpoint(TestCase):
    def test_get_s3_endpoint(self):
        eq_('s3.amazonaws.com', get_s3_endpoint('us-east-1'))
        eq_('s3.amazonaws.com', get_s3_endpoint('foo'))
        eq_('s3-eu-west-1.amazonaws.com', get_s3_endpoint('eu-west-1'))
        eq_('s3.cn-north-1.amazonaws.com.cn', get_s3_endpoint('cn-north-1'))

    def test_is_valid_endpoint(self):
        eq_(True, is_valid_endpoint('s3.amazonaws.com'))
        eq_(True, is_valid_endpoint('s3.cn-north-1.amazonaws.com.cn'))
