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

from minio import Minio
from minio.models import Filter, ReplicationConfig, Status

client = Minio(
    endpoint="play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

config = ReplicationConfig(
    role="REPLACE-WITH-ACTUAL-ROLE",
    rules=[
        ReplicationConfig.Rule(
            destination=ReplicationConfig.Destination(
                "REPLACE-WITH-ACTUAL-DESTINATION-BUCKET-ARN",
            ),
            status=Status.ENABLED,
            delete_marker_replication=ReplicationConfig.DeleteMarkerReplication(
                Status.DISABLED,
            ),
            rule_filter=Filter(
                Filter.And(
                    "TaxDocs",
                    {"key1": "value1", "key2": "value2"},
                ),
            ),
            rule_id="rule1",
            priority=1,
        ),
    ],
)
client.set_bucket_replication(bucket_name="my-bucket", config=config)
