# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2018 Minio, Inc.
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

from nose.tools import eq_, raises
from unittest import TestCase

from minio.helpers import is_storageclass_header,is_amz_header,is_supported_header,amzprefix_user_metadata

class HeaderTests(TestCase):
    def test_is_supported_header(self):
        eq_(is_supported_header("content-type"),False)
        eq_(is_supported_header("Content-Type"),False)
        eq_(is_supported_header("cOntent-TypE"),False)
        eq_(is_supported_header("x-amz-meta-me"),False)
        eq_(is_supported_header("Cache-Control"),True)
        eq_(is_supported_header("content-encoding"),True)
        eq_(is_supported_header("content-disposition"),True)
        eq_(is_supported_header("content-language"),True)
        eq_(is_supported_header("x-amz-website-redirect-location"),True)
    def test_is_amz_header(self):
        eq_(is_amz_header("x-amz-meta-status-code"),True)
        eq_(is_amz_header("X-Amz-Meta-status-code"),True)
        eq_(is_amz_header("X_AMZ_META-VALUE"),False)
        eq_(is_amz_header("content-type"),False)
        eq_(is_amz_header("x-amz-server-side-encryption"),True)
    def test_is_storageclass_header(self):
        eq_(is_storageclass_header("x-amz-storage-classs"),False)
        eq_(is_storageclass_header("x-amz-storage-class"),True)
    def test_amzprefix_user_metadata(self):
        metadata = {
                  'x-amz-meta-testing': 'values',
                  'x-amz-meta-setting': 'zombies',
                  'amz-meta-setting': 'zombiesddd',
                  'hhh':34,
                  'u_u': 'dd',
                  'y-fu-bar': 'zoo',
                  'Content-Type': 'application/csv',
                  'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                  'content-language':'fr'
                  }
        m = amzprefix_user_metadata(metadata)
        self.assertTrue('X-Amz-Meta-hhh',m)
        self.assertTrue('Content-Type',m)
        self.assertTrue('x-amz-storage-class',m)
        self.assertTrue('content-language',m)
        self.assertTrue('X-Amz-Meta-amz-meta-setting',m)
