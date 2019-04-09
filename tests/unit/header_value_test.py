# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2018 MinIO, Inc.
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
    header_variants = {
        "content-type": [
            "content-type",
            "Content-Type",
            "CONTENT-TYPE",
            "cONTENT-tYPE",
            "cOntent-TypE",
            "CoNTENT-tYPe",
        ],
        "x-amz-meta-me": [
            "x-amz-meta-me",
            "X-Amz-Meta-Me",
            "X-AMZ-META-ME",
            "x-aMZ-mETA-mE",
        ],
        "cache-control": [
            "cache-control" ,
            "Cache-Control" ,
            "CACHE-CONTROL" ,
            "cACHE-cONTROL" ,
            "CacHe-conTrol" ,
        ],
        "content-disposition": [
            "content-disposition",
            "Content-Disposition",
            "CONTENT-DISPOSITION",
            "cONTENT-dISPOSITION",
            "conTent-disPositioN",
        ],
        "content-language": [
            "content-language",
            "Content-Language",
            "CONTENT-LANGUAGE",
            "conTent-Language",
        ],
        "x-amz-website-redirect-location": [
            "x-amz-website-redirect-location",
            "X-Amz-Website-Redirect-Location",
            "X-AMZ-WEBSITE-REDIRECT-LOCATION",
            "x-aMZ-wEBSITE-rEDIRECT-lOCATION",
        ],
        "x-amz-meta-status-code": [
            "x-amz-meta-status-code",
            "X-Amz-Meta-Status-Code",
            "X-AMZ-META-STATUS-CODE",
            "x-aMZ-mETA-sTATUS-cODE",
        ],
        "x-amz-server-side-encryption": [
            "x-amz-server-side-encryption",
            "X-Amz-Server-Side-Encryption",
            "X-AMZ-SERVER-SIDE-ENCRYPTION",
            "x-aMZ-sERVER-sIDE-eNCRYPTION",
        ],
        "x-amz-storage-class": [
            "x-amz-storage-class",
            "X-Amz-Storage-Class",
            "X-AMZ-STORAGE-CLASS",
            "x-aMZ-sTORAGE-cLASS",
        ],
    }

    def check_ok_header(self, check_fun, header):
        for header_variant in self.header_variants.get(header, [header]):
            eq_(check_fun(header_variant), True)

    def check_bad_header(self, check_fun, header):
        for header_variant in self.header_variants.get(header, [header]):
            eq_(check_fun(header_variant), False)

    def test_is_supported_header(self):
        self.check_ok_header(is_supported_header, "content-type")
        self.check_ok_header(is_supported_header, "cache-control")
        self.check_ok_header(is_supported_header, "content-disposition")
        self.check_ok_header(is_supported_header, "content-encoding")
        self.check_ok_header(is_supported_header, "content-language")
        self.check_ok_header(is_supported_header, "x-amz-website-redirect-location")

    def test_is_not_supported_header(self):
        self.check_bad_header(is_supported_header, "x-amz-meta-me")

    def test_is_amz_header(self):
        self.check_ok_header(is_amz_header, "x-amz-meta-status-code")
        self.check_ok_header(is_amz_header, "x-amz-server-side-encryption")

    def test_is_not_amz_header(self):
        self.check_bad_header(is_amz_header, "X_AMZ_META-VALUE")
        self.check_bad_header(is_amz_header, "content-type")

    def test_is_storageclass_header(self):
        self.check_ok_header(is_storageclass_header, "x-amz-storage-class")

    def test_is_not_storageclass_header(self):
        self.check_bad_header(is_storageclass_header, "x-amz-storage-classs")

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
        self.assertTrue('Content-Type' in m)
        self.assertTrue('content-language' in m)

        self.assertTrue('X-Amz-Meta-hhh' in m)
        self.assertTrue('x-amz-storage-class' in m)
        self.assertTrue('X-Amz-Meta-amz-meta-setting' in m)
