# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 MinIO, Inc.
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

from minio.helpers import optimal_part_info, MAX_MULTIPART_OBJECT_SIZE, MIN_PART_SIZE
from minio.error import InvalidArgumentError

class TraceTest(TestCase):
    @raises(InvalidArgumentError)
    def test_input_size_wrong_default(self):
        optimal_part_info(MAX_MULTIPART_OBJECT_SIZE + 1, MIN_PART_SIZE)

    def test_configured_input_size_valid_maximum(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(MAX_MULTIPART_OBJECT_SIZE, 1024*1024*1000)
        eq_(total_parts_count, 5243)
        eq_(part_size, 1048576000)
        eq_(last_part_size, 922746880)

    def test_configured_input_size_valid(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(MAX_MULTIPART_OBJECT_SIZE/1024, 64*1024*1024)
        eq_(total_parts_count, 80)
        eq_(part_size, 67108864)
        eq_(last_part_size, 67108864)

    def test_configured_input_size_is_special_value(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(-1, 1024*1024*1000)
        eq_(total_parts_count, 5243)
        eq_(part_size, 1048576000)
        eq_(last_part_size, 922746880)

    def test_input_size_valid_maximum_default(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(MAX_MULTIPART_OBJECT_SIZE, MIN_PART_SIZE)
        eq_(total_parts_count, 9987)
        eq_(part_size, 550502400)
        eq_(last_part_size, 241172480)

    def test_input_size_valid_default(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(MAX_MULTIPART_OBJECT_SIZE/1024, MIN_PART_SIZE)
        eq_(total_parts_count, 1024)
        eq_(part_size, 5242880)
        eq_(last_part_size, 5242880)

    def test_input_size_is_special_value_default(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(-1, MIN_PART_SIZE)
        eq_(total_parts_count, 9987)
        eq_(part_size, 550502400)
        eq_(last_part_size, 241172480)
