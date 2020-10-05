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

from nose.tools import eq_

from minio import xml
from minio.sseconfig import AWS_KMS, Rule, SSEConfig


class ReplicationConfigTest(TestCase):
    def test_config(self):
        config = SSEConfig(Rule.new_sse_s3_rule())
        xml.marshal(config)

        config = xml.unmarshal(
            SSEConfig,
            """<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Rule>
    <ApplyServerSideEncryptionByDefault>
        <SSEAlgorithm>aws:kms</SSEAlgorithm>
        <KMSMasterKeyID>arn:aws:kms:us-east-1:1234/5678example</KMSMasterKeyID>
    </ApplyServerSideEncryptionByDefault>
</Rule>
</ServerSideEncryptionConfiguration>
        """,
        )
        xml.marshal(config)
        eq_(config.rule.sse_algorithm, AWS_KMS)
        eq_(
            config.rule.kms_master_key_id,
            "arn:aws:kms:us-east-1:1234/5678example",
        )
