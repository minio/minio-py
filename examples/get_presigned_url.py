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

from datetime import timedelta

from minio import Minio

client = Minio(
    "play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

# Get presigned URL string to delete 'my-object' in
# 'my-bucket' with one day expiry.
url = client.get_presigned_url(
    "DELETE",
    "my-bucket",
    "my-object",
    expires=timedelta(days=1),
)
print(url)

# Get presigned URL string to upload 'my-object' in
# 'my-bucket' with response-content-type as application/json
# and one day expiry.
url = client.get_presigned_url(
    "PUT",
    "my-bucket",
    "my-object",
    expires=timedelta(days=1),
    response_headers={"response-content-type": "application/json"},
)
print(url)

# Get presigned URL string to download 'my-object' in
# 'my-bucket' with two hours expiry.
url = client.get_presigned_url(
    "GET",
    "my-bucket",
    "my-object",
    expires=timedelta(hours=2),
)
print(url)
