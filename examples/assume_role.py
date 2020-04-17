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
#
# AssumeRoleProvider will call the Simple Token Service (STS) to retrieve
# temporary credentials.
#
# - You can't call AssumeRole as a root user on either MinIO or AWS.
#   For MinIO add a non-root user using the minio client `mc`:
#
#     mc admin user add myminio YOUR-ACCESSKEYID YOUR-SECRETACCESSKEY
#   On AWS you will need an IAM user with the sts:AssumeRole action allowed,
#   and a target role.
# - The credentials will be valid for between 15 minutes and 12 hours.
# - An access policy can be applied to the temporary credentials. The
#   resulting permissions are the intersection of the role's existing policy
#   and the optionally provided policy. You cannot grant more permissions than
#   those allowed by the policy of the role that is being assumed.
# - YOUR-ACCESSKEYID and YOUR-SECRETACCESSKEY are
#   dummy values, please replace them with original values.
# - To use minio with AWS, the `Minio` client that is passed to the
#   AssumeRoleProvider must have the endpoint 'sts.amazonaws.com', and the
#   RoleARN argument must be provided.

from minio import Minio
from minio.credentials import AssumeRoleProvider, Credentials

client = Minio('localhost:9000',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY'
               )

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

credentials_provider = AssumeRoleProvider(
    client, Policy=restricted_upload_policy)
temp_creds = Credentials(provider=credentials_provider)

# User can access the credentials for e.g. serialization
print("Retrieved temporary credentials:")
print(temp_creds.get().access_key)
print(temp_creds.get().secret_key)

# Initialize Minio client with the temporary credentials
restricted_client = Minio('localhost:9000', credentials=temp_creds)
