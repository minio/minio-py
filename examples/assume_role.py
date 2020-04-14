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
#
# Notes:
#  - You cannot use root user credentials to call AssumeRole.
#  - YOUR-ACCESSKEYID and YOUR-SECRETACCESSKEY are
#    dummy values, please replace them with original values.

from minio import Minio
from minio.credentials import AssumeRoleProvider, Credentials

client = Minio('localhost:9000',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY',
               region='us-east-1', secure=False)

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

credentials_provider = AssumeRoleProvider(client, Policy=restricted_upload_policy)
temp_creds = Credentials(provider=credentials_provider)

# User can access the credentials for e.g. serialization
print("Retrieved temporary credentials:")
print(temp_creds.get().access_key)
print(temp_creds.get().secret_key)

# Initialize Minio client with the temporary credentials
restricted_client = Minio('localhost:9000', credentials=temp_creds, region='us-east-1', secure=False)
