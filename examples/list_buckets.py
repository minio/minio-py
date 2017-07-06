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

# Note: YOUR-ACCESSKEYID and YOUR-SECRETACCESSKEY are
# dummy values, please replace them with original values.

import sys
sys.path.append('/home/vadmeste/work/python/minio-py/')

from minio import Minio
from minio.credentials import iam_aws_credentials 

client = Minio('localhost:9000', credentials=iam_aws_credentials(role_name="RoleName"), secure=False)

buckets = client.list_buckets()

for bucket in buckets:
    print(bucket.name, bucket.creation_date)
