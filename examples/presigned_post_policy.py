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
from minio import PostPolicy
from minio.error import ResponseError

post_policy = PostPolicy()
# set bucket name location for uploads.
post_policy.set_bucket_name('my-bucketname')
# set key prefix for all incoming uploads.
post_policy.set_key_startswith('my-objectname')
# set content length for incoming uploads.
post_policy.set_content_length_range(10, 1024)

# set expiry 10 days into future.
expires_date = datetime.utcnow() + timedelta(days=10)
post_policy.set_expires(expires_date)

client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

try:
    url, signed_form_data = client.presigned_post_policy(post_policy)

    curl_cmd = (
        ['curl -X POST {0}'.format(url)] +
        ['-F {0}={1}'.format(k, v) for k, v in signed_form_data.items()] +
        ['-F file=@<FILE>']
    )

    # print curl command to upload files.
    print(' '.join(curl_cmd))
except ResponseError as err:
    print(err)
