# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2019 MinIO, Inc.
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


from minio import Minio
from minio.select import (CSVInputSerialization, CSVOutputSerialization,
                          SelectRequest)

client = Minio(
    "s3.amazonaws.com",
    access_key="YOUR-ACCESSKEY",
    secret_key="YOUR-SECRETKEY",
)

with client.select_object_content(
        "my-bucket",
        "my-object.csv",
        SelectRequest(
            "select * from S3Object",
            CSVInputSerialization(),
            CSVOutputSerialization(),
            request_progress=True,
        ),
) as result:
    for data in result.stream():
        print(data.decode())
    print(result.stats())
