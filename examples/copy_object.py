# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2016-2020 MinIO, Inc.
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

# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2016-2020 MinIO, Inc.
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
from datetime import datetime, timezone

from minio import Minio
from minio.commonconfig import REPLACE, CopySource

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
    # Setup a client instance
    client = client_from_env()
    if client == None:
        client = client_from_play()
    
    # Create source and destination buckets
    source_bucket_name = "copy-source-bucket"+str(randint(10000,99999))
    client.make_bucket(source_bucket_name)
    dest_bucket_name = "copy-dest-bucket"+str(randint(10000,99999))
    client.make_bucket(dest_bucket_name)
    print(dest_bucket_name)

    # Create source object
    client.put_object(source_bucket_name, "my-source-object", io.BytesIO(b"hello"), 5,)
    
    # copy an object from a bucket to another.
    result = client.copy_object(
        dest_bucket_name,
        "my-object-1",
        CopySource(source_bucket_name, "my-source-object"),
    )
    print(result.object_name, result.version_id)

    # copy an object with condition.
    result = client.copy_object(
        dest_bucket_name,
        "my-object-2",
        CopySource(
            source_bucket_name,
            "my-source-object",
            modified_since=datetime(2014, 4, 1, tzinfo=timezone.utc),
        ),
    )
    print(result.object_name, result.version_id)

    # copy an object from a bucket with replacing metadata.
    metadata = {"test_meta_key": "test_meta_value"}
    result = client.copy_object(
        dest_bucket_name,
        "my-object-3",
        CopySource(source_bucket_name, "my-source-object"),
        metadata=metadata,
        metadata_directive=REPLACE,
    )
    print(result.object_name, result.version_id)

if __name__ == '__main__':
    main()
