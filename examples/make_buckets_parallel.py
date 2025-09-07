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

from minio import Minio

client = Minio(
    "play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

# Create multiple buckets in parallel.
results = client.make_buckets_parallel(["my-bucket1", "my-bucket2"])

# Create buckets in parallel with custom worker count.
client.make_buckets_parallel(["bucket1", "bucket2", "bucket3"], max_workers=3, location="us-east-1")

# Create buckets in parallel on specific region.
client.make_buckets_parallel(["bucket1", "bucket2", "bucket3"], location="us-east-1")

# Create buckets in parallel with object-lock feature on specific region.
client.make_buckets_parallel(["bucket1", "bucket2", "bucket3"], location="us-east-1", object_lock=True)