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

def test_make_bucket(client):
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    # Get unique bucket_name, object_name.
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    client.make_bucket(bucket_name)
    # Check if bucket was created properly.
    client.bucket_exists(bucket_name)
    # Remove buckets
    client.remove_bucket(bucket_name)
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
        client.remove_bucket(bucket_name+'.unique')

def test_list_buckets(client):
    bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # List all buckets.
        buckets = client.list_buckets()
        for bucket in buckets:
            # bucket object should be of a valid value.
            if bucket.name and bucket.creation_date:
                continue
            raise ValueError(bucket)
    finally:
        client.remove_bucket(bucket_name)

def test_fput_object_small_file(client, testfile):
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # upload local small file.
        print("Upload a small file through putObject")
        if is_s3:
            client.fput_object(bucket_name, object_name+'-f', testfile,
                               metadata={'x-amz-storage-class': 'STANDARD_IA'})
        else:
            client.fput_object(bucket_name, object_name+'-f', testfile)
    finally:
        client.remove_object(bucket_name, object_name+'-f')
        client.remove_bucket(bucket_name)

def test_fput_large_file(client, largefile):
    # upload local large file through multipart.
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        print("Upload a largefile through multipart upload")
        if is_s3:
            client.fput_object(bucket_name, object_name+'-large', largefile,
                               metadata={'x-amz-storage-class': 'STANDARD_IA'})
        else:
            client.fput_object(bucket_name, object_name+'-large', largefile)

        client.stat_object(bucket_name, object_name+'-large')
    finally:
        client.remove_object(bucket_name, object_name+'-large')
        client.remove_bucket(bucket_name)

def test_copy_object(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # Put a file
        print("Upload a streaming object of 1MiB")
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_name+'-f', KB_1_reader, KB_1)
        # Copy a file
        print("Perform a server side copy of an object")
        client.copy_object(bucket_name, object_name+'-copy',
                           '/'+bucket_name+'/'+object_name+'-f')

        client.stat_object(bucket_name, object_name+'-copy')

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
    finally:
        client.remove_object(bucket_name, object_name+'-f')
        client.remove_object(bucket_name, object_name+'-copy')
        client.remove_bucket(bucket_name)

def test_put_object(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        MB_11 = 11*1024*1024 # 11MiB.
        MB_11_reader = LimitedRandomReader(MB_11)
        # Put a file
        print("Upload a streaming object of 1MiB")
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)
        client.stat_object(bucket_name, object_name)
        # Put a large file
        print("Upload a streaming object of 11MiB")
        client.put_object(bucket_name, object_name+'-metadata',
                          MB_11_reader, MB_11,
                          metadata={'x-amz-meta-testing': 'value'})
        print("Stat on the uploaded object check if it exists")
        # Fetch saved stat metadata on a previously uploaded object with metadata.
        st_obj = client.stat_object(bucket_name, object_name+'-metadata')
        if 'X-Amz-Meta-Testing' not in st_obj.metadata:
            raise ValueError('Metadata key \'x-amz-meta-testing\' not found')
        value = st_obj.metadata['X-Amz-Meta-Testing']
        if value != 'value':
            raise ValueError('Metadata key has unexpected'
                             ' value {0}'.format(value))
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_object(bucket_name, object_name+'-metadata')
        client.remove_bucket(bucket_name)

def test_remove_object(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_name, KB_1_reader, KB_1)
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_get_object(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)
        newfile = 'newfile جديد'
        # Get a full object
        print("Download a full object, iterate on response to save to disk")
        object_data = client.get_object(bucket_name, object_name)
        with open(newfile, 'wb') as file_data:
            shutil.copyfileobj(object_data, file_data)
    finally:
        os.remove(newfile)
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)

def test_fget_object(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)
        newfile_f = 'newfile-f 新'
        # Get a full object locally.
        print("Download a full object and save locally at path")
        client.fget_object(bucket_name, object_name, newfile_f)
    finally:
        os.remove(newfile_f)
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)

def test_list_objects(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-1", MB_1_reader, MB_1)
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-2", MB_1_reader, MB_1)
        # List all object paths in bucket.
        print("Listing using ListObjects")
        objects = client.list_objects(bucket_name, recursive=True)
        for obj in objects:
            _, _, _, _, _, _ = obj.bucket_name, obj.object_name, \
                    obj.last_modified, \
                    obj.etag, obj.size, \
                    obj.content_type
    finally:
        client.remove_object(bucket_name, object_name+"-1")
        client.remove_object(bucket_name, object_name+"-2")
        client.remove_bucket(bucket_name)

def test_list_objects_v2(client):
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-1", MB_1_reader, MB_1)
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-2", MB_1_reader, MB_1)
        # List all object paths in bucket using V2 API.
        print("Listing using ListObjectsV2")
        objects = client.list_objects_v2(bucket_name, recursive=True)
        for obj in objects:
            _, _, _, _, _, _ = obj.bucket_name, obj.object_name, \
                               obj.last_modified, \
                               obj.etag, obj.size, \
                               obj.content_type
    finally:
        client.remove_object(bucket_name, object_name+"-1")
        client.remove_object(bucket_name, object_name+"-2")
        client.remove_bucket(bucket_name)

def test_presigned_get_object(client):
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where())
    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)

        presigned_get_object_url = client.presigned_get_object(bucket_name,
                object_name)
        response = _http.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                    'GET',
                    bucket_name,
                    object_name).get_exception()
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)

def test_presigned_put_object(client):
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where())

    bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)

        presigned_put_object_url = client.presigned_put_object(bucket_name,
                                                               object_name)
        MB_1 = 1024*1024 # 1MiB.
        response = _http.urlopen('PUT', presigned_put_object_url, LimitedRandomReader(MB_1))
        if response.status != 200:
            raise ResponseError(response,
                                'PUT',
                                bucket_name,
                                object_name).get_exception()

        client.stat_object(bucket_name, object_name)
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)

def test_presigned_post_policy(client):
    bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # Post policy.
        policy = PostPolicy()
        policy.set_bucket_name(bucket_name)
        policy.set_key_startswith('objectPrefix/')

        expires_date = datetime.utcnow()+timedelta(days=10)
        policy.set_expires(expires_date)
        client.presigned_post_policy(policy)
    finally:
        client.remove_bucket(bucket_name)

def test_get_bucket_policy(client):
    bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        policy_name = client.get_bucket_policy(bucket_name)
        if policy_name != Policy.NONE:
            raise ValueError('Policy name is invalid ' + policy_name)
    finally:
        client.remove_bucket(bucket_name)

def test_set_bucket_policy(client):
    bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
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
    finally:
        client.remove_bucket(bucket_name)

def test_remove_objects(client):
    bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        # Upload some new objects to prepare for multi-object delete test.
        print("Prepare for remove_objects() test.")
        object_names = []
        for i in range(10):
            curr_object_name = "prefix"+"-{}".format(i)
            client.put_object(bucket_name, curr_object_name, LimitedRandomReader(MB_1), MB_1)
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
    finally:
        # Try to clean everything to keep our server intact
        client.remove_objects(bucket_name, object_names)
        client.remove_bucket(bucket_name)

def test_remove_bucket(client):
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
    # Remove a bucket. This operation will only work if your bucket is empty.
    finally:
        print("Deleting buckets and finishing tests.")
        if is_s3:
            client.remove_bucket(bucket_name+'.unique')
        else:
            client.remove_bucket(bucket_name)

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
    # import sys
    # client.trace_on(sys.stderr)

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

    test_make_bucket(client)
    test_list_buckets(client)
    test_fput_object_small_file(client, testfile)
    test_fput_large_file(client, largefile)
    test_copy_object(client)
    test_put_object(client)

    test_get_object(client)
    test_fget_object(client)
    test_list_objects(client)
    test_list_objects_v2(client)
    test_presigned_get_object(client)
    test_presigned_put_object(client)
    test_presigned_post_policy(client)

    test_get_bucket_policy(client)
    test_set_bucket_policy(client)

    # Remove all objects.
    test_remove_object(client)
    test_remove_objects(client)
    test_remove_bucket(client)

    # Remove temporary files.
    if not is_mint_env:
        os.remove(testfile)
        os.remove(largefile)

if __name__ == "__main__":
    # Execute only if run as a script
    main()
