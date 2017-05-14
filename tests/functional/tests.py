#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 Minio, Inc.
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

from minio import Minio, PostPolicy, CopyConditions
from minio.policy import Policy
from minio.error import (ResponseError, PreconditionFailed,
                         BucketAlreadyOwnedByYou, BucketAlreadyExists)

from faker import Factory

def main():
    """
    Functional testing of minio python library.
    """
    fake = Factory.create()
    client = Minio('play.minio.io:9000',
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
    # client.trace_on(sys.stderr)

    # Make a new bucket.
    bucket_name = 'minio-pytest'

    client.make_bucket(bucket_name)

    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    if is_s3:
        client.make_bucket(bucket_name+'.unique',
                           location='us-west-1')

    ## Check if return codes a valid from server.
    if is_s3:
        try:
            client.make_bucket(bucket_name+'.unique',
                               location='us-west-1')
        except BucketAlreadyOwnedByYou as err:
            pass
        except BucketAlreadyExists as err:
            pass
        except ResponseError as err:
            raise

    # Check if bucket was created properly.
    client.bucket_exists(bucket_name)
    if is_s3:
        client.bucket_exists(bucket_name+'.unique')

    # List all buckets.
    buckets = client.list_buckets()
    for bucket in buckets:
        _, _ = bucket.name, bucket.creation_date

    with open('testfile', 'wb') as file_data:
        file_data.write(fake.text().encode('utf-8'))
    file_data.close()

    # Put a file
    file_stat = os.stat('testfile')
    with open('testfile', 'rb') as file_data:
        client.put_object(bucket_name, object_name, file_data,
                          file_stat.st_size)
    file_data.close()

    with open('largefile', 'wb') as file_data:
        for i in range(0, 104857):
            file_data.write(fake.text().encode('utf-8'))
    file_data.close()

    # Fput a file
    client.fput_object(bucket_name, object_name+'-f', 'testfile')
    if is_s3:
        client.fput_object(bucket_name, object_name+'-f', 'testfile',
                           metadata={'x-amz-storage-class': 'STANDARD_IA'})

    # Fput a large file.
    client.fput_object(bucket_name, object_name+'-large', 'largefile')
    if is_s3:
        client.fput_object(bucket_name, object_name+'-large', 'largefile',
                           metadata={'x-amz-storage-class': 'STANDARD_IA'})

    # Copy a file
    client.copy_object(bucket_name, object_name+'-copy',
                       '/'+bucket_name+'/'+object_name+'-f')

    try:
        copy_conditions = CopyConditions()
        copy_conditions.set_match_etag('test-etag')
        client.copy_object(bucket_name, object_name+'-copy',
                           '/'+bucket_name+'/'+object_name+'-f',
                           copy_conditions)
    except PreconditionFailed as err:
        if err.message != 'At least one of the preconditions you specified did not hold.':
            raise

    # Fetch stats on your object.
    client.stat_object(bucket_name, object_name)

    # Fetch stats on your object.
    client.stat_object(bucket_name, object_name+'-f')

    # Fetch stats on your large object.
    client.stat_object(bucket_name, object_name+'-large')

    # Fetch stats on your object.
    client.stat_object(bucket_name, object_name+'-copy')

    # Get a full object
    object_data = client.get_object(bucket_name, object_name,
                                    request_headers={'x-amz-meta-testing': 'value'})
    with open('newfile', 'wb') as file_data:
        for data in object_data:
            file_data.write(data)
    file_data.close()

    # Get a full object locally.
    client.fget_object(bucket_name, object_name, 'newfile-f',
                       request_headers={'x-amz-meta-testing': 'value'})

    client.fput_object(bucket_name, object_name+'-f', 'testfile',
                       metadata={'x-amz-meta-testing': 'value'})

    stat = client.fget_object(bucket_name, object_name+'-f', 'newfile-f-custom')
    if not stat.metadata.has_key('X-Amz-Meta-Testing'):
        raise ValueError('Metadata key \'x-amz-meta-testing\' not found')
    value = stat.metadata['X-Amz-Meta-Testing']
    if value != 'value':
        raise ValueError('Metadata key has unexpected'
                         ' value {0}'.format(value))

    # List all object paths in bucket.
    print("Listing using ListObjects")
    objects = client.list_objects(bucket_name, recursive=True)
    for obj in objects:
        _, _, _, _, _, _ = obj.bucket_name, obj.object_name, \
                           obj.last_modified, \
                           obj.etag, obj.size, \
                           obj.content_type

    # List all object paths in bucket using V2 API.
    print("Listing using ListObjectsV2")
    objects = client.list_objects_v2(bucket_name, recursive=True)
    for obj in objects:
        _, _, _, _, _, _ = obj.bucket_name, obj.object_name, \
                           obj.last_modified, \
                           obj.etag, obj.size, \
                           obj.content_type

    presigned_get_object_url = client.presigned_get_object(bucket_name, object_name)
    response = _http.urlopen('GET', presigned_get_object_url)
    if response.status != 200:
        raise ResponseError(response,
                            'GET',
                            bucket_name,
                            object_name).get_exception()

    presigned_put_object_url = client.presigned_put_object(bucket_name, object_name)
    value = fake.text().encode('utf-8')
    data = io.BytesIO(value).getvalue()
    response = _http.urlopen('PUT', presigned_put_object_url, body=data)
    if response.status != 200:
        raise ResponseError(response,
                            'PUT',
                            bucket_name,
                            object_name).get_exception()

    object_data = client.get_object(bucket_name, object_name)
    if object_data.read() != value:
        raise ValueError('Bytes not equal')

    # Post policy.
    policy = PostPolicy()
    policy.set_bucket_name(bucket_name)
    policy.set_key_startswith('objectPrefix/')

    expires_date = datetime.utcnow()+timedelta(days=10)
    policy.set_expires(expires_date)
    client.presigned_post_policy(policy)

    # Remove all objects.
    client.remove_object(bucket_name, object_name)
    client.remove_object(bucket_name, object_name+'-f')
    client.remove_object(bucket_name, object_name+'-large')
    client.remove_object(bucket_name, object_name+'-copy')

    policy_name = client.get_bucket_policy(bucket_name)
    if policy_name != Policy.NONE:
        raise ValueError('Policy name is invalid ' + policy_name)

    # Set read-only policy successfully.
    client.set_bucket_policy(bucket_name, '1/', Policy.READ_ONLY)

    # Set read-write policy successfully.
    client.set_bucket_policy(bucket_name, '1/', Policy.READ_WRITE)

    # Reset policy to NONE.
    client.set_bucket_policy(bucket_name, '', Policy.NONE)

    # Validate if the policy is reverted back to NONE.
    policy_name = client.get_bucket_policy(bucket_name)
    if policy_name != Policy.NONE:
        raise ValueError('Policy name is invalid ' + policy_name)

    # Upload some new objects to prepare for multi-object delete test.
    print("Prepare for remove_objects() test.")
    object_names = []
    for i in range(10):
        curr_object_name = object_name+"-{}".format(i)
        # print("object-name: {}".format(curr_object_name))
        client.fput_object(bucket_name, curr_object_name, "testfile")
        object_names.append(curr_object_name)

    # delete the objects in a single library call.
    print("Performing remove_objects() test.")
    del_errs = client.remove_objects(bucket_name, object_names)
    had_errs = False
    for del_err in del_errs:
        had_errs = True
        print("Remove objects err is {}".format(del_err))
    if had_errs:
        print("Removing objects FAILED - it had unexpected errors.")
        raise
    else:
        print("Removing objects worked as expected.")

    # Remove a bucket. This operation will only work if your bucket is empty.
    print("Deleting buckets and finishing tests.")
    client.remove_bucket(bucket_name)
    if client._endpoint_url.startswith("s3.amazonaws"):
        client.remove_bucket(bucket_name+'.unique')

    # Remove temporary files.
    os.remove('testfile')
    os.remove('newfile')
    os.remove('newfile-f')
    os.remove('largefile')
    os.remove('newfile-f-custom')

if __name__ == "__main__":
    # Execute only if run as a script
    main()
