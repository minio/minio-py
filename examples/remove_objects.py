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

import io
import os
from random import randint

from minio import Minio
from minio.commonconfig import ENABLED
from minio.deleteobjects import DeleteObject
from minio.versioningconfig import VersioningConfig


def client_from_env() -> Minio:
    url = os.environ.get("MINIO_ADDRESS")
    user = os.environ.get("MINIO_ACCESS_KEY")
    pw = os.environ.get("MINIO_SECRET_KEY")
    sec_var = os.environ.get("MINIO_SECURE", 'off')
    if sec_var == 'on':
        sec = True
    else:
        sec = False

    if url or user or pw:
        client = Minio(
            url,
            access_key=user,
            secret_key=pw,
            secure=sec
        )
        return client
    else:
        return None


def client_from_play() -> Minio:
    client = Minio(
        'play.min.io',
        access_key='Q3AM3UQ867SPQQA43P2F',
        secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG'
    )
    return client


def main():
    # Setup a client instance
    client = client_from_env()
    if client is None:
        client = client_from_play()

    # Create bucket
    bucket_name = "my-bucket" + str(randint(10000, 99999))
    client.make_bucket(bucket_name)
    print(bucket_name)

    # Create objects
    for i in range(1, 4):
        client.put_object(
            bucket_name,
            "my-object" +
            str(i),
            io.BytesIO(b"hello"),
            5,
        )

    # Create objects in my/prefix/
    for i in range(1, 10):
        client.put_object(
            bucket_name,
            "my/prefix/" +
            str(i),
            io.BytesIO(b"hello"),
            5,
        )

    # Create not-my-object
    client.put_object(bucket_name, "not-my-object", io.BytesIO(b"hello"), 5,)

    # Remove list of objects.
    errors = client.remove_objects(
        bucket_name,
        [
            DeleteObject("my-object1"),
            DeleteObject("my-object2"),
            DeleteObject("my-object3", "13f88b18-8dcd-4c83-88f2-8631fdb6250c"),
        ],
    )
    for error in errors:
        print("error occured when deleting object", error)

    # Remove a prefix recursively.
    delete_object_list = map(
        lambda x: DeleteObject(x.object_name),
        client.list_objects(bucket_name, "my/prefix/", recursive=True),
    )
    errors = client.remove_objects(bucket_name, delete_object_list)
    for error in errors:
        print("error occured when deleting object", error)


if __name__ == '__main__':
    main()
