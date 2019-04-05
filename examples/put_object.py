# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 MinIO, Inc.
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

# Note: YOUR-ACCESSKEYID, YOUR-SECRETACCESSKEY, my-testfile, my-bucketname and
# my-objectname are dummy values, please replace them with original values.

import os

from minio import Minio
from minio.error import ResponseError
from examples.progress import Progress

client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

# Put a file with default content-type.
try:
    with open('my-testfile', 'rb') as file_data:
        file_stat = os.stat('my-testfile')
        client.put_object('my-bucketname', 'my-objectname',
                          file_data, file_stat.st_size)
except ResponseError as err:
    print(err)

# Put a file with 'application/csv'
try:
    with open('my-testfile.csv', 'rb') as file_data:
        file_stat = os.stat('my-testfile.csv')
        client.put_object('my-bucketname', 'my-objectname', file_data,
                          file_stat.st_size, content_type='application/csv')
except ResponseError as err:
    print(err)

# Put a file with progress.
progress = Progress()
try:
    with open('my-testfile', 'rb') as file_data:
        file_stat = os.stat('my-testfile')
        client.put_object('my-bucketname', 'my-objectname',
                          file_data, file_stat.st_size, progress=progress)
except ResponseError as err:
    print(err)
