# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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
from datetime import datetime, timedelta
from urllib.request import urlopen

from examples.progress import Progress
from minio import Minio
from minio.commonconfig import GOVERNANCE, Tags
from minio.retention import Retention
from minio.sse import SseCustomerKey, SseKMS, SseS3

client = Minio(
    endpoint="play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

# Upload data.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload unknown sized data.
with urlopen(
    "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.81.tar.xz",
) as data:
    result = client.put_object(
        bucket_name="my-bucket",
        object_name="my-object",
        data=data,
        length=-1,
        part_size=10*1024*1024,
    )
    print(
        f"created {result.object_name} object; etag: {result.etag}, "
        f"version-id: {result.version_id}",
    )

# Upload data with content-type.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    content_type="application/csv",
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with metadata.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    user_metadata={"My-Project": "one"},
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with customer key type of server-side encryption.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    sse=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with KMS type of server-side encryption.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    sse=SseKMS("KMS-KEY-ID", {"Key1": "Value1", "Key2": "Value2"}),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with S3 type of server-side encryption.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    sse=SseS3(),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with tags, retention and legal-hold.
date = datetime.utcnow().replace(
    hour=0, minute=0, second=0, microsecond=0,
) + timedelta(days=30)
tags = Tags(for_object=True)
tags["User"] = "jsmith"
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    tags=tags,
    retention=Retention(GOVERNANCE, date),
    legal_hold=True,
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)

# Upload data with progress bar.
result = client.put_object(
    bucket_name="my-bucket",
    object_name="my-object",
    data=io.BytesIO(b"hello"),
    length=5,
    progress=Progress(),
)
print(
    f"created {result.object_name} object; etag: {result.etag}, "
    f"version-id: {result.version_id}",
)
