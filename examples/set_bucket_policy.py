# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2016 Minio, Inc.
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
from minio.policy import Policy

client = Minio('s3.amazonaws.com', secure=True,
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

# Make a new bucket
try:
    # Set policy Policy.READ_ONLY to bucket 'my-bucketname' which
    # enables 'my-bucketname' readable by everyone.
    client.set_bucket_policy('my-bucketname', '', Policy.READ_ONLY)

    # Set policy Policy.READ_WRITE to bucket 'my-bucketname' and
    # prefix 'public-folder/' which enables
    # 'my-bucketname/public-folder/' read/writeable by everyone.
    client.set_bucket_policy('my-bucketname', 'public-folder/',
                             Policy.READ_WRITE)

    # Set policy Policy.WRITE_ONLY to bucket 'my-bucketname' and
    # prefix 'incoming' which enables 'my-bucketname/incoming'
    # writeable by everyone.
    client.set_bucket_policy('my-bucketname', 'incoming',
                             Policy.WRITE_ONLY)

    # Set policy Policy.NONE to bucket 'my-bucketname' which
    # removes existing policy and set no access to everyone.
    client.set_bucket_policy('my-bucketname', '', Policy.NONE)
except ResponseError as err:
    print(err)
