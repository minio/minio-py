#!/usr/bin/env python
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

import os
import io
import uuid
import urllib3
import certifi

from datetime import datetime, timedelta

from minio import Minio, Acl, PostPolicy
from minio.error import ResponseError

from faker import Factory

def main():
    """
    Functional testing of minio python library.
    """
    fake = Factory.create()
    client = Minio('play.minio.io:9002',
                   'Q3AM3UQ867SPQQA43P2F',
                   'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

    _http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED',
        ca_certs=certifi.where()
    )

    # Get unique bucket_name, object_name.
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()

    # Enable trace
    # client.trace_on()

    # Make a new bucket.
    print(client.make_bucket(bucket_name))

    # Check if bucket was created properly.
    print(client.bucket_exists(bucket_name))

    # Set bucket name to private.
    print(client.set_bucket_acl(bucket_name, Acl.private()))

    # Print current bucket acl.
    print(client.get_bucket_acl(bucket_name))

    # List all buckets.
    buckets = client.list_buckets()
    for bucket in buckets:
        print(bucket.name, bucket.creation_date)

    with open('testfile', 'wb') as file_data:
        file_data.write(fake.text().encode('utf-8'))
    file_data.close()

    # Put a file
    file_stat = os.stat('testfile')
    with open('testfile', 'rb') as file_data:
        client.put_object(bucket_name, object_name, file_data, file_stat.st_size)
    file_data.close()

    # Fput a file
    print(client.fput_object(bucket_name, object_name+'-f', 'testfile'))

    # Fetch stats on your object.
    print(client.stat_object(bucket_name, object_name))

    # Get a full object
    object_data = client.get_object(bucket_name, object_name)
    with open('newfile', 'wb') as file_data:
        for data in object_data:
            file_data.write(data)
    file_data.close()

    # Get a full object locally.
    print(client.fget_object(bucket_name, object_name, 'newfile-f'))

    # List all object paths in bucket.
    objects = client.list_objects(bucket_name, recursive=True)
    for obj in objects:
        print(obj.bucket_name, obj.object_name, obj.last_modified, \
            obj.etag, obj.size, obj.content_type)

    presigned_get_object_url = client.presigned_get_object(bucket_name, object_name)
    response = _http.urlopen('GET', presigned_get_object_url)
    if response.status != 200:
        response_error = ResponseError(response)
        raise response_error.get(bucket_name, object_name)

    presigned_put_object_url = client.presigned_put_object(bucket_name, object_name)
    value = fake.text().encode('utf-8')
    data = io.BytesIO(value).getvalue()
    response = _http.urlopen('PUT', presigned_put_object_url, body=data)
    if response.status != 200:
        response_error = ResponseError(response)
        raise response_error.put(bucket_name, object_name)

    object_data = client.get_object(bucket_name, object_name)
    if object_data.read() != value:
        raise ValueError('Bytes not equal')

    # Post policy.
    policy = PostPolicy()
    policy.set_bucket_name('bucket-name')
    policy.set_key_startswith('objectPrefix/')

    expires_date = datetime.utcnow()+timedelta(days=10)
    policy.set_expires(expires_date)
    print(client.presigned_post_policy(policy))

    # Remove an object.
    print(client.remove_object(bucket_name, object_name))
    print(client.remove_object(bucket_name, object_name+'-f'))

    # Remove a bucket. This operation will only work if your bucket is empty.
    print(client.remove_bucket(bucket_name))

    # Remove temporary files.
    os.remove('testfile')
    os.remove('newfile')
    os.remove('newfile-f')

if __name__ == "__main__":
    # Execute only if run as a script
    main()
