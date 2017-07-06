#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016, 2017 Minio, Inc.
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
import uuid
import shutil
from random import random

from string import ascii_lowercase
from datetime import datetime, timedelta

import urllib3
import certifi

from minio import Minio, PostPolicy, CopyConditions
from minio.policy import Policy
from minio.error import (ResponseError, PreconditionFailed,
                         BucketAlreadyOwnedByYou, BucketAlreadyExists)

class LimitedRandomReader(object):
    """
    LimitedRandomReader returns a Reader that upon read
    returns random data, but stops with EOF after *limit*
    bytes.

    LimitedRandomReader is compatible with BufferedIOBase.

    returns a class:`LimitedRandomReader` that upon read
       provides random data and stops with EOF after *limit*
       bytes

    :param limit: Trigger EOF after limit bytes.
    """
    def __init__(self, limit):
        self._limit = limit
        self._offset_location = 0

    def read(self, amt=64*1024):
        """
        Similar to :meth:`io.read`, with amt option.

        :param amt:
            How much of the content to read.
        """
        # If offset is bigger than size. Treat it as EOF return here.
        if self._offset_location == self._limit:
            # return empty bytes to indicate EOF.
            return b''

        # make translation table from 0..255 to 97..122
        bal = [c.encode('ascii') for c in ascii_lowercase]
        amt = min(amt, self._limit - self._offset_location)
        data = b''.join([bal[int(random() * 26)] for _ in range(amt)])
        self._offset_location += len(data)
        return data

def main():
    """
    Functional testing of minio python library.
    """
    access_key = os.getenv('ACCESS_KEY', 'Q3AM3UQ867SPQQA43P2F')
    secret_key = os.getenv('SECRET_KEY',
                           'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
    server_endpoint = os.getenv('SERVER_ENDPOINT', 'play.minio.io:9000')
    secure = os.getenv('ENABLE_HTTPS', '1') == '1'
    if server_endpoint == 'play.minio.io:9000':
        access_key = 'Q3AM3UQ867SPQQA43P2F'
        secret_key = 'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG'
        secure = True

    is_s3 = server_endpoint.startswith("s3.amazonaws")
    client = Minio(server_endpoint, access_key, secret_key, secure=secure)
    # Check if we are running in the mint environment.
    is_mint_env = os.path.exists(os.getenv('DATA_DIR', '/mint/data'))

    _http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED',
        ca_certs=certifi.where()
    )

    # Get unique bucket_name, object_name.
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()

    # Enable trace
    # client.trace_on(sys.stderr)
    client.make_bucket(bucket_name)

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
        # bucket object should be of a valid value.
        if bucket.name and bucket.creation_date:
            continue
        raise ValueError(bucket)

    newfile = 'newfile جديد'
    newfile_f = 'newfile-f 新'

    testfile = 'datafile-1-MB'
    largefile = 'datafile-11-MB'
    if is_mint_env:
        data_dir = os.getenv('DATA_DIR')
        ## Choose data files
        testfile = os.path.join(data_dir, 'datafile-1-MB')
        largefile = os.path.join(data_dir, 'datafile-65-MB')
    else:
        with open(testfile, 'wb') as file_data:
            shutil.copyfileobj(LimitedRandomReader(1024*1024), file_data)
        with open(largefile, 'wb') as file_data:
            shutil.copyfileobj(LimitedRandomReader(11*1024*1024), file_data)

    # upload local small file.
    print("Upload a small file through putObject")
    client.fput_object(bucket_name, object_name+'-f', testfile)
    if is_s3:
        client.fput_object(bucket_name, object_name+'-f', testfile,
                           metadata={'x-amz-storage-class': 'STANDARD_IA'})

    # upload local large file through multipart.
    print("Upload a largefile through multipart upload")
    client.fput_object(bucket_name, object_name+'-large', largefile)
    if is_s3:
        client.fput_object(bucket_name, object_name+'-large', largefile,
                           metadata={'x-amz-storage-class': 'STANDARD_IA'})

    # Fetch stats on your large object.
    client.stat_object(bucket_name, object_name+'-large')

    # Copy a file
    print("Perform a server side copy of an object")
    client.copy_object(bucket_name, object_name+'-copy',
                       '/'+bucket_name+'/'+object_name+'-f')

    print("Perform a server side copy of an object with pre-conditions and fail")
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
    client.stat_object(bucket_name, object_name+'-copy')

    # Put a file
    MB_1 = 1024*1024 # 1MiB.
    MB_1_reader = LimitedRandomReader(MB_1)
    print("Upload a streaming object of 1MiB")
    client.put_object(bucket_name, object_name, MB_1_reader, MB_1)

    # Put a large file
    MB_11 = 11*1024*1024 # 11MiB.
    MB_11_reader = LimitedRandomReader(MB_11)
    print("Upload a streaming object of 11MiB")
    client.put_object(bucket_name, object_name+'-metadata',
                      MB_11_reader, MB_11,
                      metadata={'x-amz-meta-testing': 'value'})

    print("Stat on the uploaded object check if it exists")
    # Fetch stats on your object.
    client.stat_object(bucket_name, object_name)

    # Fetch saved stat metadata on a previously uploaded object with metadata.
    st_obj = client.stat_object(bucket_name, object_name+'-metadata')
    if 'X-Amz-Meta-Testing' not in st_obj.metadata:
        raise ValueError('Metadata key \'x-amz-meta-testing\' not found')
    value = st_obj.metadata['X-Amz-Meta-Testing']
    if value != 'value':
        raise ValueError('Metadata key has unexpected'
                         ' value {0}'.format(value))

    # Get a full object
    print("Download a full object, iterate on response to save to disk")
    object_data = client.get_object(bucket_name, object_name)
    with open(newfile, 'wb') as file_data:
        shutil.copyfileobj(object_data, file_data)

    # Get a full object locally.
    print("Download a full object and save locally at path")
    client.fget_object(bucket_name, object_name, newfile_f)

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

    presigned_get_object_url = client.presigned_get_object(bucket_name,
                                                           object_name)
    response = _http.urlopen('GET', presigned_get_object_url)
    if response.status != 200:
        raise ResponseError(response,
                            'GET',
                            bucket_name,
                            object_name).get_exception()

    presigned_put_object_url = client.presigned_put_object(bucket_name,
                                                           object_name)

    response = _http.urlopen('PUT', presigned_put_object_url,
                             body=LimitedRandomReader(MB_1))
    if response.status != 200:
        raise ResponseError(response,
                            'PUT',
                            bucket_name,
                            object_name).get_exception()

    client.get_object(bucket_name, object_name)

    # Post policy.
    policy = PostPolicy()
    policy.set_bucket_name(bucket_name)
    policy.set_key_startswith('objectPrefix/')

    expires_date = datetime.utcnow()+timedelta(days=10)
    policy.set_expires(expires_date)
    client.presigned_post_policy(policy)

    # Remove all objects.
    client.remove_object(bucket_name, object_name)
    client.remove_object(bucket_name, object_name+'-metadata')
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
        client.put_object(bucket_name, curr_object_name,
                          LimitedRandomReader(MB_1), MB_1)
        object_names.append(curr_object_name)

    # delete the objects in a single library call.
    print("Performing remove_objects() test.")
    del_errs = client.remove_objects(bucket_name, object_names)
    had_errs = False
    for del_err in del_errs:
        had_errs = True
        print("Remove objects err is {}".format(del_err))
    if had_errs:
        raise("Removing objects FAILED - it had unexpected errors.")
    else:
        print("Removing objects worked as expected.")

    # Remove a bucket. This operation will only work if your bucket is empty.
    print("Deleting buckets and finishing tests.")
    client.remove_bucket(bucket_name)
    if is_s3:
        client.remove_bucket(bucket_name+'.unique')

    # Remove temporary files.
    if not is_mint_env:
        os.remove(testfile)
        os.remove(largefile)

    os.remove(newfile)
    os.remove(newfile_f)

if __name__ == "__main__":
    # Execute only if run as a script
    main()
