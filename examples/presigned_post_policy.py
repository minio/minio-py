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

# Note: my-bucketname, my-objectname, YOUR-ACCESSKEYID, and
# YOUR-SECRETACCESSKEY are dummy values, please replace them with original
# values.

from datetime import datetime, timedelta

from minio import Minio
from minio.datatypes import PostPolicy

client = Minio(
    "s3.amazonaws.com",
    access_key="YOUR-ACCESSKEYID",
    secret_key="YOUR-SECRETACCESSKEY",
)

policy = PostPolicy(
    "bucket_name", datetime.utcnow() + timedelta(days=10),
)
policy.add_starts_with_condition("key", "objectPrefix/")
policy.add_content_length_range_condition(1*1024*1024, 10*1024*1024)

form_data = client.presigned_post_policy(policy)

curl_cmd = (
    "curl -X POST "
    "https://s3.amazonaws.com/bucket_name "
    "{0} -F file=@<FILE>"
).format(
    " ".join(["-F {0}={1}".format(k, v) for k, v in form_data.items()]),
)
print(curl_cmd)
