# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2020 MinIO, Inc.
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

# Note: YOUR-ACCESSKEYID and YOUR-SECRETACCESSKEY are
# dummy values, please replace them with original values.
import io

from minio import Minio
from minio.credentials.assume_role import assume_role

client = Minio('localhost:9000',
              # access_key='YOUR-ACCESSKEYID',
              # secret_key='YOUR-SECRETACCESSKEY')
                access_key='newuser',
               secret_key='newuser123', region='us-east-1', secure=False)

restricted_upload_policy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::uploads/2020/*"
      ],
      "Sid": "Upload-access-to-specific-bucket-only"
    }
  ]
} 
"""


temp_creds = assume_role(client, Policy=restricted_upload_policy)

print(temp_creds)
print(temp_creds.get().secret_key)

restricted_client = Minio('localhost:9000', credentials=temp_creds, region='us-east-1', secure=False)

restricted_client.put_object('uploads', '2020/testobject', io.BytesIO(b'data'), length=4)

