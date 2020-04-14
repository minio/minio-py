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

# Note: YOUR-ACCESSKEYID, YOUR-SECRETACCESSKEY, my-bucketname and my-prefix
# are dummy values, please replace them with original values.

from minio import Minio
from minio.error import ResponseError

client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

# Remove a prefix recursively.
try:
    names = map(
        lambda x: x.object_name,
        client.list_objects_v2('my-bucketname', 'my-prefix', recursive=True)
    )
    for err in client.remove_objects('my-bucketname', names):
        print("Deletion Error: {}".format(err))
except ResponseError as err:
    print(err)
