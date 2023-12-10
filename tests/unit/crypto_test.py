# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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

from io import BytesIO
from unittest import TestCase

from urllib3.response import HTTPResponse

from minio.crypto import decrypt, encrypt


class CryptoTest(TestCase):
    def test_correct(self):
        secret = "topsecret"
        plaintext = "Hello MinIO!"
        encrypted = encrypt(plaintext.encode(), secret)
        decrypted = decrypt(
            HTTPResponse(body=BytesIO(encrypted), preload_content=False),
            secret,
        ).decode()
        if hasattr(self, "assertEquals"):
            self.assertEquals(plaintext, decrypted)
        else:
            self.assertEqual(plaintext, decrypted)

    def test_wrong(self):
        secret = "topsecret"
        secret2 = "othersecret"
        plaintext = "Hello MinIO!"
        encrypted = encrypt(plaintext.encode(), secret)
        self.assertRaises(
            ValueError,
            decrypt,
            HTTPResponse(body=BytesIO(encrypted), preload_content=False),
            secret2,
        )
