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

# Note: YOUR-ACCESSKEYID, YOUR-SECRETACCESSKEY, my-bucketname, my-objectname and
# my-filepath dummy values, please replace them with original values.

from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG', secure=True)

# Put an object 'my-objectname' with contents from 'my-filepath'
try:
    client.fput_object('album', 'my-testfile', 'my-testfile', progress=True)
except ResponseError as err:
    print(err)

# Put on object 'my-objectname-csv' with contents from
# 'my-filepath.csv' as 'application/csv'.
try:
    client.fput_object('album', 'my-testfile2',
                       'my-testfile2', content_type='application/csv', progress=True)
except ResponseError as err:
    print(err)
