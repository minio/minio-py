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

import mock

from nose.tools import eq_, raises
from unittest import TestCase

from minio.helpers import optimal_part_info
from minio.error import InvalidArgumentError

class TraceTest(TestCase):
    @raises(InvalidArgumentError)
    def test_input_size_wrong(self):
        optimal_part_info(5000000000000000000)

    def test_input_size_valid_maximum(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(5497558138880)
        eq_(total_parts_count, 9987)
        eq_(part_size, 550502400)
        eq_(last_part_size, 241172480)

    def test_input_size_valid(self):
        total_parts_count, part_size, last_part_size = optimal_part_info(-1)
        eq_(total_parts_count, 9987)
        eq_(part_size, 550502400)
        eq_(last_part_size, 241172480)
