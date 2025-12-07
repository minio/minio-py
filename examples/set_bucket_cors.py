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
from minio.models import CORSConfig

client = Minio(
    endpoint="play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

config = CORSConfig(
    rules=[
        CORSConfig.CORSRule(
            allowed_headers=["*"],
            allowed_methods=["PUT", "POST", "DELETE"],
            allowed_origins=["http://www.example.com"],
            expose_headers=["x-amz-server-side-encryption"],
            max_age_seconds=3000,
        ),
        CORSConfig.CORSRule(
            allowed_methods=["GET"],
            allowed_origins=["*"],
        ),
    ],
)

client.set_bucket_cors(bucket_name="my-bucket", config=config)
