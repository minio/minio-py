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
from minio.sse import SseCustomerKey

client = Minio(
    "play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

# Download data of an object.
client.fget_object("my-bucket", "my-object", "my-filename")

# Download data of an object of version-ID.
client.fget_object(
    "my-bucket", "my-object", "my-filename",
    version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
)

# Download data of an SSE-C encrypted object.
client.fget_object(
    "my-bucket", "my-object", "my-filename",
    ssec=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
