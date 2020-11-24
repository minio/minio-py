# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2020 MinIO, Inc.
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

from datetime import datetime, timedelta, timezone
from unittest import TestCase

from nose.tools import eq_

from minio import xml
from minio.commonconfig import COMPLIANCE, GOVERNANCE
from minio.retention import Retention


class RetentionTest(TestCase):
    def test_config(self):
        config = Retention(GOVERNANCE, datetime.utcnow() + timedelta(days=10))
        xml.marshal(config)

        config = xml.unmarshal(
            Retention,
            """<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <Mode>COMPLIANCE</Mode>
   <RetainUntilDate>2020-10-02T00:00:00Z</RetainUntilDate>
</Retention>""",
        )
        xml.marshal(config)
        eq_(config.mode, COMPLIANCE)
        eq_(
            config.retain_until_date,
            datetime(2020, 10, 2, 0, 0, 0, 0, timezone.utc),
        )
