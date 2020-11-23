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

# Note: YOUR-ACCESSKEYID, YOUR-SECRETACCESSKEY, my-bucketname and my-objectname
# are dummy values, please replace them with original values.

from minio import Minio
from minio.sse import SseCustomerKey

client = Minio(
    "s3.amazonaws.com",
    access_key="YOUR-ACCESSKEYID",
    secret_key="YOUR-SECRETACCESSKEY",
)

# Get object information.
result = client.stat_object("my-bucketname", "my-objectname")
print(
    "last-modified: {0}, size: {1}".format(
        result.last_modified, result.size,
    ),
)

# Get object information of version-ID.
result = client.stat_object(
    "my-bucketname", "my-objectname",
    version_id="dfbd25b3-abec-4184-a4e8-5a35a5c1174d",
)
print(
    "last-modified: {0}, size: {1}".format(
        result.last_modified, result.size,
    ),
)

# Get SSE-C encrypted object information.
result = client.stat_object(
    "my-bucketname", "my-objectname",
    ssec=SseCustomerKey(b"32byteslongsecretkeymustprovided"),
)
print(
    "last-modified: {0}, size: {1}".format(
        result.last_modified, result.size,
    ),
)
