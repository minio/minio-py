# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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

from datetime import datetime, timedelta

from minio import Minio
from minio import PostPolicy

policy = PostPolicy()
## set bucket name location for uploads.
policy.set_bucket_name('bucketName')
## set key prefix for all incoming uploads.
policy.set_key_startswith('objectName')
## set content length for incoming uploads.
policy.set_content_length_range(10, 1024)

## set expiry 10 days into future.
expires_date = datetime.utcnow()+timedelta(days=10)
policy.set_expires(expires_date)

client = Minio('https://s3.amazonaws.com',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

curl_str = 'curl -X POST https://bucketName.s3.amazonaws.com/'
curl_cmd = [curl_str]
signed_form_data = client.presigned_post_policy(policy)
for field in signed_form_data:
    curl_cmd.append('-F {0}={1}'.format(field, signed_form_data[field]))

## print curl command to upload files.
curl_cmd.append('-F file=@<FILE>')
print ' '.join(curl_cmd)
