# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage.
# Copyright (C) 2018 Minio, Inc.
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

client = Minio('s3.amazonaws.com', secure=True,
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

try:
    # Print all policies of bucket 'my-bucketname'.
    print(client.list_bucket_policies('my-bucketname'))

    # Print all policies of bucket 'my-bucketname' and prefix 'my-prefix'.
    print(client.list_bucket_policies('my-bucketname', 'my-prefix'))
except ResponseError as err:
    print(err)
