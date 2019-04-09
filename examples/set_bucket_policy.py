# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage.
# Copyright (C) 2016 MinIO, Inc.
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

# Note: YOUR-ACCESSKEYID, YOUR-SECRETACCESSKEY and my-bucketname are
# dummy values, please replace them with original values.

from minio import Minio
from minio.error import ResponseError
import json

client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

# Make a new bucket
try:
    # Set bucket policy to read-only for bucket 'my-bucketname'
    policy_read_only = {
        "Version":"2012-10-17",
        "Statement":[
            {
            "Sid":"",
            "Effect":"Allow",
            "Principal":{"AWS":"*"},
            "Action":"s3:GetBucketLocation",
            "Resource":"arn:aws:s3:::my-bucketname"
            },
            {
            "Sid":"",
            "Effect":"Allow",
            "Principal":{"AWS":"*"},
            "Action":"s3:ListBucket",
            "Resource":"arn:aws:s3:::my-bucketname"
            },
            {
            "Sid":"",
            "Effect":"Allow",
            "Principal":{"AWS":"*"},
            "Action":"s3:GetObject",
            "Resource":"arn:aws:s3:::my-bucketname/*"
            }
        ]
    }
    client.set_bucket_policy('my-bucketname', json.dumps(policy_read_only))

    # Set bucket policy to read-write for bucket 'my-bucketname'
    policy_read_write = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": ["s3:GetBucketLocation"],
                "Sid": "",
                "Resource": ["arn:aws:s3:::my-bucketname"],
                "Effect": "Allow",
                "Principal": {"AWS": "*"}
            },
            {
                "Action": ["s3:ListBucket"],
                "Sid": "",
                "Resource": ["arn:aws:s3:::my-bucketname"],
                "Effect": "Allow",
                "Principal": {"AWS": "*"}
            },
            {
                "Action": ["s3:ListBucketMultipartUploads"],
                "Sid": "",
                "Resource": ["arn:aws:s3:::my-bucketname"],
                "Effect": "Allow",
                "Principal": {"AWS": "*"}
            },
            {
                "Action": ["s3:ListMultipartUploadParts",
                            "s3:GetObject",
                            "s3:AbortMultipartUpload",
                            "s3:DeleteObject",
                            "s3:PutObject"],
                "Sid": "",
                "Resource": ["arn:aws:s3:::my-bucketname/*"],
                "Effect": "Allow",
                "Principal": {"AWS": "*"}
            }
        ]
    }
    client.set_bucket_policy('my-bucketname', json.dumps(policy_read_write))

    # Set bucket policy to write-only for bucket 'my-bucketname'
    policy_write_only = {
        "Version":"2012-10-17",
        "Statement":[
            {
                "Sid":"",
                "Effect":"Allow",
                "Principal":{"AWS":"*"},
                "Action":"s3:GetBucketLocation",
                "Resource":"arn:aws:s3:::my-bucketname"
            },
            {"Sid":"",
            "Effect":"Allow",
            "Principal":{"AWS":"*"},
            "Action":"s3:ListBucketMultipartUploads",
            "Resource":"arn:aws:s3:::my-bucketname"
            },
            {
                "Sid":"",
                "Effect":"Allow",
                "Principal":{"AWS":"*"},
                "Action":[
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload",
                    "s3:DeleteObject",
                    "s3:PutObject"],
                "Resource":"arn:aws:s3:::my-bucketname/*"
            }
        ]
    }
    client.set_bucket_policy('my-bucketname', json.dumps(policy_write_only))

except ResponseError as err:
    print(err)
