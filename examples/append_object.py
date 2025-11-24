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
from urllib.request import urlopen

from minio import Minio

client = Minio(
    endpoint="play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

# Upload data.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello, "),
    length=7,
)
print(f"created {result.object_name} object; etag: {result.etag}")

# Append data.
result = client.append_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"world"),
    length=5,
)
print(f"appended {result.object_name} object; etag: {result.etag}")

# Append data in chunks.
with urlopen(
    "https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.13.12.tar.xz",
) as stream:
    result = client.append_object(
        bucket_name="my-bucket",
        object_name="my-object",
        stream=stream,
        length=148611164,
        chunk_size=5*1024*1024,
    )
    print(f"appended {result.object_name} object; etag: {result.etag}")

# Append unknown sized data.
with urlopen(
    "https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.14.3.tar.xz",
) as stream:
    result = client.append_object(
        bucket_name="my-bucket",
        object_name="my-object",
        stream=stream,
        chunk_size=5*1024*1024,
    )
    print(f"appended {result.object_name} object; etag: {result.etag}")
