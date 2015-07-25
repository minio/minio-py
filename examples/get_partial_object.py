# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 compatible cloud storage, (C) 2015 Minio, Inc.
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
import hashlib

from minio import Minio

__author__ = 'minio'

client = Minio('https://s3.amazonaws.com',
               access_key='YOUR-ACCESSKEYID',
               secret_key='YOUR-SECRETACCESSKEY')

# Offset the download by 2 bytes and retrieve a total of 4 bytes.
data = client.get_partial_object('bucket', 'key', 2, 4)

# Example generating sha256 of partial data
sha256 = hashlib.sha256()
for datum in data:
    sha256.update(datum)
print sha256.hexdigest()
