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

from unittest import TestCase

from minio import xml
from minio.commonconfig import COMPLIANCE, GOVERNANCE
from minio.objectlockconfig import DAYS, YEARS, ObjectLockConfig


class ObjectLockConfigTest(TestCase):
    def test_config(self):
        config = ObjectLockConfig(GOVERNANCE, 15, DAYS)
        xml.marshal(config)

        config = xml.unmarshal(
            ObjectLockConfig,
            """<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <ObjectLockEnabled>Enabled</ObjectLockEnabled>
   <Rule>
      <DefaultRetention>
         <Mode>COMPLIANCE</Mode>
         <Years>3</Years>
      </DefaultRetention>
   </Rule>
</ObjectLockConfiguration>""",
        )
        xml.marshal(config)
        self.assertEqual(config.mode, COMPLIANCE)
        self.assertEqual(config.duration, (3, YEARS))
