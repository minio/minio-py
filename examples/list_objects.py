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

import os
import io
from random import randint

from minio import Minio


def client_from_env()->Minio:
    url = os.environ.get("MINIO_ADDRESS")
    user = os.environ.get("MINIO_ACCESS_KEY")
    pw = os.environ.get("MINIO_SECRET_KEY")
    sec_var = os.environ.get("MINIO_SECURE",'off')
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

def client_from_play()->Minio:
    client = Minio(
        'play.min.io',
        access_key='Q3AM3UQ867SPQQA43P2F',
        secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG'
    )
    return client

def main():
    client = client_from_env()
    if client == None:
        client = client_from_play()
    
    # Create bucket
    bucket_name = "my-bucket"+str(randint(10000,99999))
    client.make_bucket(bucket_name)
    print(bucket_name)

    # Create object
    client.put_object(bucket_name, "my-object", io.BytesIO(b"hello"), 5,)

    # Create objects in folder
    for i in range(1,10):
        client.put_object(bucket_name, "my/prefix/world/"+str(i), io.BytesIO(b"hello"), 5,)

    # List objects information.
    objects = client.list_objects(bucket_name)
    for obj in objects:
        print(obj)

    # List objects information whose names starts with "my/prefix/".
    objects = client.list_objects(bucket_name, prefix="my/prefix/")
    print("my/prefix/")
    for obj in objects:
        print(obj)

    # List objects information recursively.
    objects = client.list_objects(bucket_name, recursive=True)
    print("recursive")
    for obj in objects:
        print(obj)

    # List objects information recursively whose names starts with
    # "my/prefix/".
    print("recursive in my/prefix/")
    objects = client.list_objects(
        bucket_name, prefix="my/prefix/", recursive=True,
    )
    for obj in objects:
        print(obj)

    # List objects information recursively after object name
    # "my/prefix/world/1".
    print("recursive after my/prefix/world/1")
    objects = client.list_objects(
        bucket_name, recursive=True, start_after="my/prefix/world/1",
    )
    for obj in objects:
        print(obj)
    
if __name__ == '__main__':
    main()
