# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) [2024] - [2026] MinIO, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Download from MinIO over RDMA into a pre-allocated host buffer."""

import os
from minio import Minio

client = Minio(
    endpoint=os.environ.get("MINIO_ENDPOINT", "coe01:9000"),
    access_key=os.environ.get("MINIO_ACCESS_KEY", "minioadmin"),
    secret_key=os.environ.get("MINIO_SECRET_KEY", "minioadmin"),
    secure=False,
    enable_rdma=True,
)

size = 1 << 20
dst = bytearray(size)

# When into= is set on get_object the call returns the bytes-transferred
# count (int) instead of the streaming GetObjectResponse.
n = client.get_object(
    bucket_name="rdma-test",
    object_name="hello-rdma",
    into=dst,
    length=size,
)
print(f"bytes_transferred={n}")
print(f"first 16 bytes: {bytes(dst[:16])!r}")
