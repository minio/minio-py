# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
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

"""Unit tests for CRC32C. Whichever backend _crc32c_update resolves to must
agree with the lookup table implementation it replaces."""

from unittest import TestCase

from minio.checksum import CRC32C, _crc32c_table_update

_BLOB = bytes(range(256)) * 512


class CRC32CTest(TestCase):
    def test_check_value(self):
        hasher = CRC32C()
        hasher.update(b"123456789")
        self.assertEqual(hasher.sum(), bytes.fromhex("e3069283"))

    def test_matches_lookup_table(self):
        for data in [b"", b"a", b"123456789", _BLOB]:
            hasher = CRC32C()
            hasher.update(data)
            self.assertEqual(
                hasher.sum(),
                _crc32c_table_update(0, data).to_bytes(4, "big"),
            )

    def test_update_in_chunks(self):
        hasher = CRC32C()
        for i in range(0, len(_BLOB), 7919):
            hasher.update(_BLOB, i, min(7919, len(_BLOB) - i))
        single = CRC32C()
        single.update(_BLOB)
        self.assertEqual(hasher.sum(), single.sum())

    def test_reset(self):
        hasher = CRC32C()
        hasher.update(b"123456789")
        hasher.reset()
        hasher.update(b"123456789")
        self.assertEqual(hasher.sum(), bytes.fromhex("e3069283"))
