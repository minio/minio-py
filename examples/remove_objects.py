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

from minio import Minio
from minio.deleteobjects import DeleteObject

client = Minio(
    endpoint="play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)

# Remove list of objects.
errors = client.remove_objects(
    bucket_name="my-bucket",
    delete_object_list=[
        DeleteObject(name="my-object1"),
        DeleteObject(name="my-object2"),
        DeleteObject(
            name="my-object3",
            version_id="13f88b18-8dcd-4c83-88f2-8631fdb6250c",
        ),
    ],
)
for error in errors:
    print("error occurred when deleting object", error)

# Remove a prefix recursively.
delete_object_list = map(
    lambda x: DeleteObject(x.object_name),
    client.list_objects(
        bucket_name="my-bucket",
        prefix="my/prefix/",
        recursive=True,
    ),
)
errors = client.remove_objects(
    bucket_name="my-bucket",
    delete_object_list=delete_object_list,
)
for error in errors:
    print("error occurred when deleting object", error)
