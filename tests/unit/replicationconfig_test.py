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
from minio.commonconfig import DISABLED, ENABLED, AndOperator, Filter, Tags
from minio.replicationconfig import (DeleteMarkerReplication, Destination,
                                     ReplicationConfig, Rule)


class ReplicationConfigTest(TestCase):
    def test_config(self):
        tags = Tags()
        tags.update({"key1": "value1", "key2": "value2"})
        config = ReplicationConfig(
            "REPLACE-WITH-ACTUAL-ROLE",
            [
                Rule(
                    Destination(
                        "REPLACE-WITH-ACTUAL-DESTINATION-BUCKET-ARN",
                    ),
                    ENABLED,
                    delete_marker_replication=DeleteMarkerReplication(
                        DISABLED,
                    ),
                    rule_filter=Filter(AndOperator("TaxDocs", tags)),
                    rule_id="rule1",
                    priority=1,
                ),
            ],
        )
        xml.marshal(config)

        config = xml.unmarshal(
            ReplicationConfig,
            """<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Role>arn:aws:iam::35667example:role/CrossRegionReplicationRoleForS3</Role>
  <Rule>
    <ID>rule1</ID>
    <Status>Enabled</Status>
    <Priority>1</Priority>
    <DeleteMarkerReplication>
       <Status>Disabled</Status>
    </DeleteMarkerReplication>
    <Filter>
       <And>
           <Prefix>TaxDocs</Prefix>
           <Tag>
             <Key>key1</Key>
             <Value>value1</Value>
           </Tag>
           <Tag>
             <Key>key1</Key>
             <Value>value1</Value>
           </Tag>
       </And>
    </Filter>
    <Destination>
      <Bucket>arn:aws:s3:::exampletargetbucket</Bucket>
    </Destination>
  </Rule>
</ReplicationConfiguration>""",
        )
        xml.marshal(config)
