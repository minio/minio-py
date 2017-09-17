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
import inspect
import json
from random import random

from string import ascii_lowercase
import time
import traceback
from datetime import datetime, timedelta

import urllib3
import certifi

from minio import Minio, PostPolicy, CopyConditions
from minio.policy import Policy
from minio.error import (ResponseError, PreconditionFailed,
                         BucketAlreadyOwnedByYou, BucketAlreadyExists)

# Constants
PASS = 'PASS'
FAIL = 'FAIL'
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

def new_log_result(meth, alert = None):
    # Initialize and return log content in log_output dictionary
    # Collect args in args_arr
    args_list = inspect.getargspec(meth).args
    # Remove the first args_list element, which is always "self"
    del args_list[0]
    # Initialize the args , (arg: value), dictionary
    args_dict = {value: '' for key, value in enumerate(args_list)}
    # Create and return log output content
    return {'name': 'minio-py',\
            'function': meth.__name__+'('+', '.join(args_list)+')',\
            'description': '',\
            'args': args_dict,\
            'duration': 0,\
            'alert': alert,\
            'message': None,\
            'error': None,\
            'status': PASS}

def print_json(log_output):
    print(json.dumps(log_output))

def test_make_bucket(client):
    start_time = time.time()

    log_output = new_log_result(client.make_bucket)
    log_output['description'] = 'Tests make_bucket api'
    # Get a unique bucket_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()

    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    try:
        # Create a bucket
        client.make_bucket(bucket_name)
        # Check if bucket was created properly
        client.bucket_exists(bucket_name)
        # Remove bucket
        client.remove_bucket(bucket_name)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()

    if is_s3:
        try:
            log_output['args']['location'] = location = 'us-east-1'
            client.make_bucket(bucket_name+'.unique', location)
        except BucketAlreadyOwnedByYou as err:
            # Expected this exception. Test passes
            pass
        except BucketAlreadyExists as err:
            # Expected this exception. Test passes
            pass
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
        try:
            client.remove_bucket(bucket_name+'.unique')
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_list_buckets(client):
    start_time = time.time()

    log_output = new_log_result(client.list_buckets)
    log_output['description'] = 'Tests list_buckets api'
    # Get a unique bucket_name
    bucket_name = uuid.uuid4().__str__()

    try:
        client.make_bucket(bucket_name)
        # List all buckets.
        buckets = client.list_buckets()
        for bucket in buckets:
            # bucket object should be of a valid value.
            if bucket.name and bucket.creation_date:
                continue
            raise ValueError('list_bucket api failure')
    except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    finally:
        client.remove_bucket(bucket_name)
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_fput_object_small_file(client, testfile):
    start_time = time.time()

    log_output = new_log_result(client.fput_object)
    log_output['description'] = 'Tests fput_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    log_output['args']['file_path'] = testfile
    log_output['args']['metadata'] = metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    try:
        client.make_bucket(bucket_name)
        # upload local small file.
        if is_s3:
            client.fput_object(bucket_name, object_name+'-f', testfile,
                               metadata)
        else:
            client.fput_object(bucket_name, object_name+'-f', testfile)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name+'-f')
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_fput_large_file(client, largefile):
    start_time = time.time()

    log_output = new_log_result(client.fput_object)
    log_output['description'] = 'Tests fput_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    log_output['args']['file_path'] = largefile
    log_output['args']['metadata'] = metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    # upload local large file through multipart.
    try:
        client.make_bucket(bucket_name)
        if is_s3:
            client.fput_object(bucket_name, object_name+'-large', largefile,
                               metadata)
        else:
            client.fput_object(bucket_name, object_name+'-large', largefile)

        client.stat_object(bucket_name, object_name+'-large')
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name+'-large')
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_copy_object(client):
    start_time = time.time()

    log_output = new_log_result(client.copy_object)
    log_output['description'] = 'Tests copy_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    object_name = uuid.uuid4().__str__()
    log_output['args']['object_source'] = object_source = object_name+'-source'
    log_output['args']['object_name'] = object_copy = object_name+'-copy'
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1)
        # Perform a server side copy of an object
        client.copy_object(bucket_name, object_copy,
                           '/'+bucket_name+'/'+object_source)

        client.stat_object(bucket_name, object_copy)
        # Perform a server side copy of an object with pre-conditions and fail
        try:
            etag = 'test-etag'
            copy_conditions = CopyConditions()
            copy_conditions.set_match_etag(etag)
            log_output['args']['conditions'] = {'set_match_etag': etag}
            client.copy_object(bucket_name, object_copy,
                               '/'+bucket_name+'/'+object_source,
                               copy_conditions)
        except PreconditionFailed as err:
            if err.message != 'At least one of the preconditions you specified did not hold.':
                log_output['message'] = err
                log_output['error'] = traceback.format_exc()
                log_output['status'] = FAIL
                log_output['duration'] = duration = round(time.time() - start_time, 2)
                print_json(log_output)
                exit()
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_put_object(client):
    start_time = time.time()

    log_output = new_log_result(client.put_object)
    log_output['description'] = 'Tests put_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # Put/Upload a streaming object of 1MiB
        log_output['args']['length'] = MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        log_output['args']['data'] = 'LimitedRandomReader(MB_1)'
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)
        client.stat_object(bucket_name, object_name)
        # Put/Upload a streaming object of 11MiB
        log_output['args']['length'] = MB_11 = 11*1024*1024 # 11MiB.
        MB_11_reader = LimitedRandomReader(MB_11)
        log_output['args']['data'] = 'LimitedRandomReader(MB_11)'
        log_output['args']['metadata'] = metadata = {'x-amz-meta-testing': 'value'}
        content_type='application/octet-stream'
        client.put_object(bucket_name,
                          object_name+'-metadata',
                          MB_11_reader,
                          MB_11,
                          content_type,
                          metadata)
        # Stat on the uploaded object to check if it exists
        # Fetch saved stat metadata on a previously uploaded object with metadata.
        st_obj = client.stat_object(bucket_name, object_name+'-metadata')
        if 'X-Amz-Meta-Testing' not in st_obj.metadata:
            raise ValueError("Metadata key 'x-amz-meta-testing' not found")
        value = st_obj.metadata['X-Amz-Meta-Testing']
        if value != 'value':
            raise ValueError('Metadata key has unexpected'
                             ' value {0}'.format(value))
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_object(bucket_name, object_name+'-metadata')
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_remove_object(client):
    start_time = time.time()

    log_output = new_log_result(client.remove_object)
    log_output['description'] = 'Tests remove_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_name, KB_1_reader, KB_1)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_get_object(client):
    start_time = time.time()

    log_output = new_log_result(client.get_object)
    log_output['description'] = 'Tests get_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)
        newfile = 'newfile جديد'
        # Get/Download a full object, iterate on response to save to disk
        object_data = client.get_object(bucket_name, object_name)
        with open(newfile, 'wb') as file_data:
            # What is the point of copy? Do we want to verify something?
            shutil.copyfileobj(object_data, file_data)

    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            os.remove(newfile)
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_fget_object(client):
    start_time = time.time()

    log_output = new_log_result(client.fget_object)
    log_output['description'] = 'Tests fget_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    log_output['args']['file_path'] = newfile_f = 'newfile-f 新'
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1)
        # Get/Download a full object and save locally at path
        client.fget_object(bucket_name, object_name, newfile_f)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            os.remove(newfile_f)
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_list_objects(client):
    start_time = time.time()

    log_output = new_log_result(client.list_objects)
    log_output['description'] = 'Tests list_objects api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-1", MB_1_reader, MB_1)
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-2", MB_1_reader, MB_1)
        # List all object paths in bucket.
        log_output['args']['recursive'] = is_recursive = True
        objects = client.list_objects(bucket_name, None, is_recursive)
        for obj in objects:
            _, _, _, _, _, _ = obj.bucket_name,\
                               obj.object_name,\
                               obj.last_modified,\
                               obj.etag, obj.size,\
                               obj.content_type
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name+"-1")
            client.remove_object(bucket_name, object_name+"-2")
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_list_objects_v2(client):
    start_time = time.time()

    log_output = new_log_result(client.list_objects_v2)
    log_output['description'] = 'Tests list_objects_v2 api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-1", MB_1_reader, MB_1)
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-2", MB_1_reader, MB_1)
        # List all object paths in bucket using V2 API.
        log_output['args']['recursive'] = is_recursive = True
        objects = client.list_objects_v2(bucket_name, None, is_recursive)
        for obj in objects:
            _, _, _, _, _, _ = obj.bucket_name,\
                               obj.object_name,\
                               obj.last_modified,\
                               obj.etag, obj.size,\
                               obj.content_type
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name+"-1")
            client.remove_object(bucket_name, object_name+"-2")
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_presigned_get_object(client):
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where())
    start_time = time.time()

    log_output = new_log_result(client.presigned_get_object)
    log_output['description'] = 'Tests presigned_get_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
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
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_presigned_put_object(client):
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where())

    start_time = time.time()

    log_output = new_log_result(client.presigned_put_object)
    log_output['description'] = 'Tests presigned_put_object api'
    # Get a unique bucket_name and object_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['object_name'] = object_name = uuid.uuid4().__str__()
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
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_presigned_post_policy(client):
    start_time = time.time()

    log_output = new_log_result(client.presigned_post_policy)
    log_output['description'] = 'Tests presigned_post_policy api'
    bucket_name = uuid.uuid4().__str__()
    no_of_days = 10
    prefix = 'objectPrefix/'
    try:
        client.make_bucket(bucket_name)
        # Post policy.
        policy = PostPolicy()
        policy.set_bucket_name(bucket_name)
        policy.set_key_startswith(prefix)
        expires_date = datetime.utcnow()+timedelta(days=no_of_days)
        policy.set_expires(expires_date)
        # post_policy arg is a class. To avoid displaying meaningless value
        # for the class, policy settings are made part of the args for
        # clarity and debugging purposes.
        log_output['args']['post_policy'] = {'bucket_name': bucket_name,
                                             'prefix': prefix,
                                             'expires_in_days': no_of_days}
        client.presigned_post_policy(policy)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = 'FAIL1'
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = 'FAIL2'
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_get_bucket_policy(client):
    start_time = time.time()

    log_output = new_log_result(client.get_bucket_policy)
    log_output['description'] = 'Tests get_bucket_policy api'
    # Get a unique bucket_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        policy_name = client.get_bucket_policy(bucket_name)
        if policy_name != Policy.NONE:
            raise ValueError('Policy name is invalid: ' + policy_name)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_set_bucket_policy(client):
    start_time = time.time()

    log_output = new_log_result(client.set_bucket_policy)
    log_output['description'] = 'Tests set_bucket_policy api'
    # Get a unique bucket_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    log_output['args']['prefix'] = prefix = '1/'
    try:
        client.make_bucket(bucket_name)
        # Set read-only policy successfully.
        client.set_bucket_policy(bucket_name, prefix, Policy.READ_ONLY)
        # Set read-write policy successfully.
        client.set_bucket_policy(bucket_name, prefix, Policy.READ_WRITE)
        # Reset policy to NONE.
        # Added into log output for clarity/debugging purposes
        log_output['args']['prefix-2'] = prefix = ''
        client.set_bucket_policy(bucket_name, prefix, Policy.NONE)
        # Validate if the policy is reverted back to NONE.
        policy_name = client.get_bucket_policy(bucket_name)
        if policy_name != Policy.NONE:
            raise ValueError('Policy name is invalid ' + policy_name)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = 'FAIL1'
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = 'FAIL2'
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_remove_objects(client):
    start_time = time.time()

    log_output = new_log_result(client.remove_objects)
    log_output['description'] = 'Tests remove_objects api'
    # Get a unique bucket_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        # Upload some new objects to prepare for multi-object delete test.
        object_names = []
        for i in range(10):
            curr_object_name = "prefix"+"-{}".format(i)
            client.put_object(bucket_name, curr_object_name, LimitedRandomReader(MB_1), MB_1)
            object_names.append(curr_object_name)
        # delete the objects in a single library call.
        log_output['args']['objects_iter'] = objects_iter = object_names
        del_errs = client.remove_objects(bucket_name, objects_iter)
        for del_err in del_errs:
            raise ValueError("Remove objects err: {}".format(del_err))
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            # Try to clean everything to keep our server intact
            client.remove_objects(bucket_name, objects_iter)
            client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

def test_remove_bucket(client):
    is_s3 = client._endpoint_url.startswith("s3.amazonaws")
    is_s3 = True
    start_time = time.time()

    log_output = new_log_result(client.remove_bucket)
    log_output['description'] = 'Tests remove_bucket api'
    # Get a unique bucket_name
    log_output['args']['bucket_name'] = bucket_name = uuid.uuid4().__str__()
    try:
        if is_s3:
            log_output['args']['location'] = location = 'us-east-1'
            client.make_bucket(bucket_name+'.unique', location)
        else:
            client.make_bucket(bucket_name)
    except Exception as err:
        log_output['message'] = err
        log_output['error'] = traceback.format_exc()
        log_output['status'] = FAIL
        log_output['duration'] = duration = round(time.time() - start_time, 2)
        print_json(log_output)
        exit()
    finally:
        try:
            # Removing bucket. This operation will only work if your bucket is empty.
            if is_s3:
                client.remove_bucket(bucket_name+'.unique')
            else:
                client.remove_bucket(bucket_name)
        except Exception as err:
            log_output['message'] = err
            log_output['error'] = traceback.format_exc()
            log_output['status'] = FAIL
            log_output['duration'] = duration = round(time.time() - start_time, 2)
            print_json(log_output)
            exit()
    # Test passes
    log_output['duration'] = duration = round(time.time() - start_time, 2)
    print_json(log_output)

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
    data_dir = os.getenv('DATA_DIR')
    if data_dir == None:
       os.environ['DATA_DIR'] = data_dir = '/mint/data'
    is_mint_env = (os.path.exists(data_dir) and
                  os.path.exists(os.path.join(data_dir, 'datafile-1-MB')) and
                  os.path.exists(os.path.join(data_dir, 'datafile-11-MB')))

    # Enable trace
    # import sys
    # client.trace_on(sys.stderr)

    testfile = 'datafile-1-MB'
    largefile = 'datafile-11-MB'
    if is_mint_env :
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
