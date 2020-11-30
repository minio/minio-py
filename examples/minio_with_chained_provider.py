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

# A Chain credentials provider, provides a way of chaining multiple providers
# together and will pick the first available using priority order of the
# 'providers' list

from minio import Minio
from minio.credentials import (AWSConfigProvider, ChainedProvider,
                               EnvAWSProvider, IamAwsProvider)

client = Minio(
    "s3.amazonaws.com",
    credentials=ChainedProvider(
        [
            IamAwsProvider(),
            AWSConfigProvider(),
            EnvAWSProvider(),
        ]
    )
)

# Get information of an object.
stat = client.stat_object("my-bucket", "my-object")
print(stat)
