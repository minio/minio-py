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

import io

from minio import Minio
from minio.args import PutObjectFanOutEntry

client = Minio(
    endpoint="play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

response = client.put_object_fan_out(
    bucket_name="my-bucket",
    data=io.BytesIO(b"hello"),
    length=5,
    entries=[
        PutObjectFanOutEntry(key="fan-out.0"),
        PutObjectFanOutEntry(
            key="fan-out.1",
            tags={"Project": "Project One", "User": "jsmith"},
        ),
    ],
)
for result in response.results:
    print(
        f"created {result.key} object; etag: {result.etag}, "
        f"version-id: {result.version_id}, ",
        f"error: {result.error}",
    )
