# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2016,2017,2018 MinIO, Inc.
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

from minio.error import ResponseError

client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEY',
               secret_key='YOUR-SECRETKEY')

# Set the metadata
metadata = {"test_meta_key": "test_meta_value"}

try:
    copy_result = client.copy_object("my-bucket", "my-object",
                                     "/my-sourcebucket/my-sourceobject",
                                     metadata=metadata)
    print(copy_result)
except ResponseError as err:
    print(err)
