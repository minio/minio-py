#!/usr/bin/env python
# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016, 2017, 2018 MinIO, Inc.
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

from __future__ import division

import os
import io

from sys import exit
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
import hashlib
from threading import Thread

from minio import Minio, PostPolicy, CopyConditions
from minio.error import (APINotImplemented, NoSuchBucketPolicy, ResponseError,
                         PreconditionFailed, BucketAlreadyOwnedByYou,
                         BucketAlreadyExists, InvalidBucketError)
from minio.sse import SSE_C
from minio.sse import copy_SSE_C

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

class LogOutput(object):
    """
    LogOutput is the class for log output. It is required standard for all
    SDK tests controlled by mint.
    Here are its attributes:
            'name': name of the SDK under test, e.g. 'minio-py'
            'function': name of the method/api under test with its signature
                        The following python code can be used to
                        pull args information of a <method> and to
                        put together with the method name:
                        <method>.__name__+'('+', '.join(args_list)+')'
                        e.g. 'remove_object(bucket_name, object_name)'
            'args': method/api arguments with their values, in
                    dictionary form: {'arg1': val1, 'arg2': val2, ...}
            'duration': duration of the whole test in milliseconds,
                        defaults to 0
            'alert': any extra information user is needed to be alerted about,
                     like whether this is a Blocker/Gateway/Server related
                     issue, etc., defaults to None
            'message': descriptive error message, defaults to None
            'error': stack-trace/exception message(only in case of failure),
                     actual low level exception/error thrown by the program,
                     defaults to None
            'status': exit status, possible values are 'PASS', 'FAIL', 'NA',
                      defaults to 'PASS'
    """

    PASS = 'PASS'
    FAIL = 'FAIL'
    NA = 'NA'

    def __init__(self, meth, test_name):
        self.__args_list = inspect.getargspec(meth).args[1:]
        self.__name = 'minio-py:'+test_name
        self.__function = meth.__name__+'('+', '.join(self.__args_list)+')'
        self.__args = {}
        self.__duration = 0
        self.__alert = ''
        self.__message = None
        self.__error = None
        self.__status = self.PASS
        self.__start_time = time.time()
    @property
    def name(self): return self.__name
    @property
    def function(self): return self.__function
    @property
    def args(self): return self.__args

    @name.setter
    def name(self, val): self.__name = val
    @function.setter
    def function(self, val): self.__function = val
    @args.setter
    def args(self, val): self.__args = val

    def json_report(self, err_msg='', alert='', status=''):
        self.__args = {k: v for k, v in self.__args.items() if v and v != ''}
        entry = {'name': self.__name,
            'function': self.__function,
            'args': self.__args,
            'duration': int(round((time.time() - self.__start_time)*1000)),
            'alert': str(alert),
            'message': str(err_msg),
            'error': traceback.format_exc() if err_msg and err_msg != '' else '',
            'status': status if status and status != '' else \
                    self.FAIL if err_msg and err_msg != '' else self.PASS
        }
        return json.dumps({k: v for k, v in entry.items() if v and v != ''})

def generate_bucket_name():
    return "minio-py-test-" + uuid.uuid4().__str__()

def is_s3(client):
    return "s3.amazonaws" in client._endpoint_url

def test_make_bucket_default_region(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "make_bucket(bucket_name, location)"

    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    # Default location
    log_output.args['location'] = "default value ('us-east-1')"
    try:
        # Create a bucket with default bucket location
        client.make_bucket(bucket_name)
        # Check if bucket was created properly
        log_output.function = 'bucket_exists(bucket_name)'
        client.bucket_exists(bucket_name)
        # Remove bucket
        log_output.function = 'remove_bucket(bucket_name)'
        client.remove_bucket(bucket_name)
    except Exception as err:
        raise Exception(err)
    # Test passes
    log_output.function = 'make_bucket(bucket_name, location)'
    print(log_output.json_report())

def test_make_bucket_with_region(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "make_bucket(bucket_name, location)"

    # Only test make bucket with region against AWS S3
    if not is_s3(client):
        return

    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    # A non-default location
    log_output.args['location'] = location = 'us-west-1'
    try:
        # Create a bucket with default bucket location
        client.make_bucket(bucket_name, location)
        # Check if bucket was created properly
        log_output.function = 'bucket_exists(bucket_name)'
        client.bucket_exists(bucket_name)
        # Remove bucket
        log_output.function = 'remove_bucket(bucket_name)'
        client.remove_bucket(bucket_name)
    except Exception as err:
        raise Exception(err)
    # Test passes
    log_output.function = 'make_bucket(bucket_name, location)'
    print(log_output.json_report())

def test_negative_make_bucket_invalid_name(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "make_bucket(bucket_name, location)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    # Default location
    log_output.args['location'] = "default value ('us-east-1')"
    # Create an array of invalid bucket names to test
    invalid_bucket_name_list = [bucket_name+'.', '.'+bucket_name, bucket_name+'...'+'abcd']
    for name in invalid_bucket_name_list:
        log_output.args['bucket_name'] = name
        try:
            # Create a bucket
            client.make_bucket(name)
            # Check if bucket was created properly
            log_output.function = 'bucket_exists(bucket_name)'
            client.bucket_exists(name)
            # Remove bucket
            log_output.function = 'remove_bucket(bucket_name)'
            client.remove_bucket(name)
        except InvalidBucketError as err:
            pass
        except Exception as err:
            raise Exception(err)
    # Test passes
    log_output.function = 'make_bucket(bucket_name, location)'
    log_output.args['bucket_name'] = invalid_bucket_name_list
    print(log_output.json_report())

def test_list_buckets(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "list_buckets(  )"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()

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
            raise Exception(err)
    finally:
        client.remove_bucket(bucket_name)
    # Test passes
    print(log_output.json_report())

def test_fput_object_small_file(client, testfile, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "fput_object(bucket_name, object_name, file_path, content_type, metadata)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    log_output.args['file_path'] = testfile
    log_output.args['metadata'] = metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    try:
        client.make_bucket(bucket_name)
        # upload local small file.
        if is_s3(client):
            client.fput_object(bucket_name, object_name+'-f', testfile,
                               metadata=metadata, sse=sse)
        else:
            client.fput_object(bucket_name, object_name+'-f', testfile, sse=sse)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name+'-f')
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_fput_object_large_file(client, largefile, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "fput_object(bucket_name, object_name, file_path, content_type, metadata)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    log_output.args['file_path'] = largefile
    log_output.args['metadata'] = metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    # upload local large file through multipart.
    try:
        client.make_bucket(bucket_name)
        if is_s3(client):
            client.fput_object(bucket_name, object_name+'-large', largefile,
                               metadata=metadata, sse=sse)
        else:
            client.fput_object(bucket_name, object_name+'-large', largefile, sse=sse)

        client.stat_object(bucket_name, object_name+'-large',sse=sse)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name+'-large')
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_fput_object_with_content_type(client, testfile, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "fput_object(bucket_name, object_name, file_path, content_type, metadata)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    log_output.args['file_path'] = testfile
    log_output.args['content_type'] = content_type = 'application/octet-stream'
    log_output.args['metadata'] = metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    try:
        client.make_bucket(bucket_name)
        # upload local small file with content_type defined.
        if is_s3(client):
            client.fput_object(bucket_name, object_name+'-f', testfile,
                               content_type, metadata=metadata)
        else:
            client.fput_object(bucket_name, object_name+'-f', testfile,
                               content_type)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name+'-f')
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_copy_object_no_copy_condition(client, log_output, ssec_copy=None, ssec=None):
    # default value for log_output.function attribute is;
    # log_output.function = "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_source'] = object_source = object_name+'-source'
    log_output.args['object_name'] = object_copy = object_name+'-copy'
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1, sse=ssec)
        client.copy_object(bucket_name, object_copy,
                           '/'+bucket_name+'/'+object_source, source_sse=ssec_copy, sse=ssec)
        st_obj = client.stat_object(bucket_name, object_copy, sse=ssec)
        validate_stat_data(st_obj, KB_1, {})
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_copy_object_with_metadata(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "copy_object(bucket_name, object_name, object_source, metadata)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_source'] = object_source = object_name+'-source'
    log_output.args['object_name'] = object_copy = object_name+'-copy'
    log_output.args['metadata'] = metadata = {"testing-string": "string", "testing-int": 1}
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1)

        # Perform a server side copy of an object
        client.copy_object(bucket_name, object_copy,
                           '/'+bucket_name+'/'+object_source,metadata=metadata)
        # Verification
        stat_obj = client.stat_object(bucket_name, object_copy)
        expected_metadata = {'x-amz-meta-testing-int': '1', 'x-amz-meta-testing-string': 'string'}
        validate_stat_data(stat_obj, KB_1, expected_metadata)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_copy_object_etag_match(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_source'] = object_source = object_name+'-source'
    log_output.args['object_name'] = object_copy = object_name+'-copy'
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1)
        # Perform a server side copy of an object
        client.copy_object(bucket_name, object_copy,
                           '/'+bucket_name+'/'+object_source)
        # Verification
        source_etag = client.stat_object(bucket_name, object_source).etag
        copy_conditions = CopyConditions()
        copy_conditions.set_match_etag(source_etag)
        log_output.args['conditions'] = {'set_match_etag': source_etag}
        client.copy_object(bucket_name, object_copy,
                           '/'+bucket_name+'/'+object_source,
                           copy_conditions)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_copy_object_negative_etag_match(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_source'] = object_source = object_name+'-source'
    log_output.args['object_name'] = object_copy = object_name+'-copy'
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1)

        try:
            # Perform a server side copy of an object
            # with incorrect pre-conditions and fail
            etag = 'test-etag'
            copy_conditions = CopyConditions()
            copy_conditions.set_match_etag(etag)
            log_output.args['conditions'] = {'set_match_etag': etag}
            client.copy_object(bucket_name, object_copy,
                               '/'+bucket_name+'/'+object_source,
                               copy_conditions)
        except PreconditionFailed as err:
            if err.message != 'At least one of the preconditions you specified did not hold.':
                raise Exception(err)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_copy_object_modified_since(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_source'] = object_source = object_name+'-source'
    log_output.args['object_name'] = object_copy = object_name+'-copy'
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1)
        # Set up the 'modified_since' copy condition
        copy_conditions = CopyConditions()
        t = (2014, 4, 1, 0, 0, 0, 0, 0, 0)
        mod_since = datetime.utcfromtimestamp(time.mktime(t))
        copy_conditions.set_modified_since(mod_since)
        date_pretty = mod_since.strftime('%c')
        log_output.args['conditions'] = {'set_modified_since':date_pretty}
        # Perform a server side copy of an object
        # and expect the copy to complete successfully
        client.copy_object(bucket_name, object_copy,
                           '/'+bucket_name+'/'+object_source,
                           copy_conditions)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_copy_object_unmodified_since(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_source'] = object_source = object_name+'-source'
    log_output.args['object_name'] = object_copy = object_name+'-copy'
    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1MiB
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_source, KB_1_reader, KB_1)
        # Set up the 'modified_since' copy condition
        copy_conditions = CopyConditions()
        t = (2014, 4, 1, 0, 0, 0, 0, 0, 0)
        unmod_since = datetime.utcfromtimestamp(time.mktime(t))
        copy_conditions.set_unmodified_since(unmod_since)
        date_pretty = unmod_since.strftime('%c')
        log_output.args['conditions'] = {'set_unmodified_since': date_pretty}
        try:
            # Perform a server side copy of an object and expect
            # the copy to fail since the creation/modification
            # time is now, way later than unmodification time, April 1st, 2014
            client.copy_object(bucket_name, object_copy,
                               '/'+bucket_name+'/'+object_source,
                               copy_conditions)
        except PreconditionFailed as err:
            if err.message != 'At least one of the preconditions you specified did not hold.':
                raise Exception(err)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_source)
            client.remove_object(bucket_name, object_copy)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def normalize_metadata(meta_data):
    norm_dict = {k.lower(): v for k, v in meta_data.items()}
    return norm_dict


def test_put_object(client, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "put_object(bucket_name, object_name, data, length, content_type, metadata)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # Put/Upload a streaming object of 1MiB
        log_output.args['length'] = MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        log_output.args['data'] = 'LimitedRandomReader(MB_1)'
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1, sse=sse)
        client.stat_object(bucket_name, object_name, sse=sse)
        # Put/Upload a streaming object of 11MiB
        log_output.args['length'] = MB_11 = 11*1024*1024 # 11MiB.
        MB_11_reader = LimitedRandomReader(MB_11)
        log_output.args['data'] = 'LimitedRandomReader(MB_11)'
        log_output.args['metadata'] = metadata = {'x-amz-meta-testing': 'value','test-key':'value2'}
        log_output.args['content_type'] = content_type='application/octet-stream'
        client.put_object(bucket_name,
                          object_name+'-metadata',
                          MB_11_reader,
                          MB_11,
                          content_type,
                          metadata,
                          sse=sse)
        # Stat on the uploaded object to check if it exists
        # Fetch saved stat metadata on a previously uploaded object with metadata.
        st_obj = client.stat_object(bucket_name, object_name+'-metadata', sse=sse)
        normalized_meta = normalize_metadata(st_obj.metadata)
        if 'x-amz-meta-testing' not in normalized_meta:
            raise ValueError("Metadata key 'x-amz-meta-testing' not found")
        value = normalized_meta['x-amz-meta-testing']
        if value != 'value':
            raise ValueError('Metadata key has unexpected'
                             ' value {0}'.format(value))
        if 'x-amz-meta-test-key' not in normalized_meta:
            raise ValueError("Metadata key 'x-amz-meta-test-key' not found")
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_object(bucket_name, object_name+'-metadata')
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_negative_put_object_with_path_segment(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "put_object(bucket_name, object_name, data, length, content_type, metadata)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = "/a/b/c/" + uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        log_output.args['length'] = 0 # Keep 0 bytes body to check for error.
        log_output.args['data'] = ''
        client.put_object(bucket_name,
                          object_name,
                          io.BytesIO(b''), 0)
    except ResponseError as err:
        if err.code != 'XMinioInvalidObjectName':
            raise err
    except Exception as err:
        raise err
    finally:
        try:
            client.remove_object(bucket_name, object_name)
        except ResponseError as err:
            if err.code != 'XMinioInvalidObjectName':
                raise err
        except Exception as err:
            raise err
        client.remove_bucket(bucket_name)
    # Test passes
    print(log_output.json_report())

def validate_stat_data(st_obj, expected_size, expected_meta):

    received_modification_time = st_obj.last_modified
    received_etag = st_obj.etag
    received_metadata = normalize_metadata(st_obj.metadata)
    received_content_type = st_obj.content_type
    received_size = st_obj.size
    received_is_dir = st_obj.is_dir

    if not isinstance(received_modification_time, time.struct_time):
        raise ValueError('Incorrect last_modified time type'
                         ', received type: ', type(received_modification_time))

    if not received_etag or received_etag == '':
        raise ValueError('No Etag value is returned.')

    # content_type by default can be either application/octet-stream or binary/octet-stream
    if received_content_type != 'application/octet-stream' and received_content_type != 'binary/octet-stream':
        raise ValueError('Incorrect content type. Expected: ',
                         "'application/octet-stream' or 'binary/octet-stream', received: ",
                          received_content_type)

    if received_size != expected_size:
        raise ValueError('Incorrect file size. Expected: 11534336',
                         ', received: ', received_size)

    if received_is_dir != False:
        raise ValueError('Incorrect file type. Expected: is_dir=False',
                         ', received: is_dir=', received_is_dir)

    if not all(i in received_metadata.items() for i in expected_meta.items()):
        raise ValueError("Metadata key 'x-amz-meta-testing' not found")

def test_stat_object(client, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "stat_object(bucket_name, object_name)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        # Put/Upload a streaming object of 1MiB
        log_output.args['length'] = MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        log_output.args['data'] = 'LimitedRandomReader(MB_1)'
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1, sse=sse)
        client.stat_object(bucket_name, object_name, sse=sse)
        # Put/Upload a streaming object of 11MiB
        log_output.args['length'] = MB_11 = 11*1024*1024 # 11MiB.
        MB_11_reader = LimitedRandomReader(MB_11)
        log_output.args['data'] = 'LimitedRandomReader(MB_11)'
        log_output.args['metadata'] = metadata = {'X-Amz-Meta-Testing': 'value'}
        log_output.args['content_type'] = content_type='application/octet-stream'

        client.put_object(bucket_name,
                          object_name+'-metadata',
                          MB_11_reader,
                          MB_11,
                          content_type,
                          metadata,
                          sse=sse)
        # Get the stat on the uploaded object
        st_obj = client.stat_object(bucket_name, object_name+'-metadata',sse=sse)
        # Verify the collected stat data.
        validate_stat_data(st_obj, MB_11, normalize_metadata(metadata))
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_object(bucket_name, object_name+'-metadata')
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_remove_object(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_object(bucket_name, object_name)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_name, KB_1_reader, KB_1)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_get_object(client, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "get_object(bucket_name, object_name, request_headers)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        newfile = 'newfile جديد'
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.make_bucket(bucket_name)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1, sse=sse)
        # Get/Download a full object, iterate on response to save to disk
        object_data = client.get_object(bucket_name, object_name, sse=sse)
        with open(newfile, 'wb') as file_data:
            shutil.copyfileobj(object_data, file_data)

    except Exception as err:
        raise Exception(err)
    finally:
        try:
            os.remove(newfile)
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_fget_object(client, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "fget_object(bucket_name, object_name, file_path, request_headers)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    log_output.args['file_path'] = newfile_f = 'newfile-f 新'
    try:
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.make_bucket(bucket_name)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1, sse=sse)
        # Get/Download a full object and save locally at path
        client.fget_object(bucket_name, object_name, newfile_f, sse=sse)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            os.remove(newfile_f)
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_get_partial_object_with_default_length(client, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "get_partial_object(bucket_name, object_name, offset, length, request_headers)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        newfile = 'newfile'
        MB_1 = 1024*1024 # 1MiB.
        length = 1000
        log_output.args['offset'] = offset = MB_1 - length
        MB_1_reader = LimitedRandomReader(MB_1)
        client.make_bucket(bucket_name)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1, sse=sse)
        # Get half of the object
        object_data = client.get_partial_object(bucket_name, object_name, offset, sse=sse)
        with open(newfile, 'wb') as file_data:
            for d in object_data:
                file_data.write(d)
        #Check if the new file is the right size
        new_file_size = os.path.getsize('./newfile')
        if new_file_size != length:
            raise ValueError('Unexpected file size after running ')
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            # os.remove(newfile)
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_get_partial_object(client, log_output, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "get_partial_object(bucket_name, object_name, offset, length, request_headers)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        newfile = 'newfile'
        MB_1 = 1024*1024 # 1MiB.
        log_output.args['offset'] = offset = int(MB_1/2)
        log_output.args['length'] = length = int(MB_1/2)-1000
        MB_1_reader = LimitedRandomReader(MB_1)
        client.make_bucket(bucket_name)
        client.put_object(bucket_name, object_name, MB_1_reader, MB_1, sse=sse)
        # Get half of the object
        object_data = client.get_partial_object(bucket_name, object_name, offset, length, sse=sse)
        with open(newfile, 'wb') as file_data:
            for d in object_data:
                file_data.write(d)
        #Check if the new file is the right size
        new_file_size = os.path.getsize('./newfile')
        if new_file_size != length:
            raise ValueError('Unexpected file size after running ')
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            # os.remove(newfile)
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_list_objects(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-1", MB_1_reader, MB_1)
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-2", MB_1_reader, MB_1)
        # List all object paths in bucket.
        log_output.args['recursive'] = is_recursive = True
        objects = client.list_objects(bucket_name, '', is_recursive)
        for obj in objects:
            _, _, _, _, _, _ = obj.bucket_name,\
                               obj.object_name,\
                               obj.last_modified,\
                               obj.etag, obj.size,\
                               obj.content_type
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name+"-1")
            client.remove_object(bucket_name, object_name+"-2")
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def count_objects(objects):
    no_of_files = 0
    for obj in objects:
        _, _, _, _, _, _ = obj.bucket_name,\
                            obj.object_name,\
                            obj.last_modified,\
                            obj.etag, obj.size,\
                            obj.content_type
        no_of_files += 1
    return no_of_files

def list_objects_api_test(client, bucket_name, expected_no, *argv):
    # argv is composed of prefix and recursive arguments of
    # list_objects api. They are both supposed to be passed as strings.
    no_of_files = count_objects(client.list_objects(bucket_name, *argv) )  # expect all objects to be listed
    if expected_no != no_of_files:
        raise ValueError("Listed no of objects ({}), does not match the expected no of objects ({})".format(no_of_files, expected_no))

def test_list_objects_with_prefix(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.

        no_of_created_files = 4
        path_prefix = ''

        # Create files and directories
        for i in range(no_of_created_files):
            str_i = str(i)
            MB_1_reader = LimitedRandomReader(MB_1)
            client.put_object(bucket_name, path_prefix + str_i + '_' + object_name, MB_1_reader, MB_1)
            path_prefix += str_i + '/'
        # Created files and directory structure
        # ._<bucket_name>/
        # |___0_<object_name>
        # |___0/
        #     |___1_<object_name>
        #     |___1/
        #         |___2_<object_name>
        #         |___2/
        #             |___3_<object_name>
        #

        # Test and verify list_objects api outputs
        # List objects recursively with NO prefix
        log_output.args['recursive'] = recursive = 'True'
        log_output.args['prefix'] = prefix = '' # no prefix
        list_objects_api_test(client, bucket_name,
                              no_of_created_files,
                              prefix, recursive)

        # List objects at the top level with no prefix and no recursive option
        # Expect only the top 2 objects to be listed
        log_output.args['recursive'] = recursive = ''
        log_output.args['prefix'] = prefix = ''
        list_objects_api_test(client, bucket_name, 2)

        # List objects for '0' directory/prefix without recursive option
        # Expect 2 object (directory '0' and '0_' object) to be listed
        log_output.args['prefix'] = prefix = '0'
        list_objects_api_test(client, bucket_name, 2, prefix)

        # List objects for '0/' directory/prefix without recursive option
        # Expect only 2 objects under directory '0/' to be listed, non-recursive
        log_output.args['prefix'] = prefix = '0/'
        list_objects_api_test(client, bucket_name, 2, prefix)

        # List objects for '0/' directory/prefix, recursively
        # Expect 2 objects to be listed
        log_output.args['prefix'] = prefix = '0/'
        log_output.args['recursive'] = recursive = 'True'
        list_objects_api_test(client, bucket_name, 3, prefix, recursive)

        # List object with '0/1/2/' directory/prefix, non-recursive
        # Expect the single object under directory '0/1/2/' to be listed
        log_output.args['prefix'] = prefix = '0/1/2/'
        list_objects_api_test(client, bucket_name, 1, prefix)

    except Exception as err:
        raise Exception(err)
    finally:
        try:
            path_prefix = ''
            for i in range(no_of_created_files):
                str_i = str(i)
                client.remove_object(bucket_name, path_prefix + str_i + '_' + object_name)
                path_prefix += str_i + '/'
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    log_output.args['recursive'] = 'Several prefix/recursive combinations are tested'
    log_output.args['prefix'] = 'Several prefix/recursive combinations are tested'
    print(log_output.json_report())

def test_list_objects_with_1001_files(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    object_name = uuid.uuid4().__str__()
    log_output.args['object_name'] = object_name + '_0 ~ ' + object_name + '_1000'
    try:
        client.make_bucket(bucket_name)
        KB_1 = 1024 # 1KiB.

        no_of_created_files = 2000
        path_prefix = ''

        # Create 1001 1KiB files under bucket_name at the same layer
        for i in range(no_of_created_files):
            str_i = str(i)
            KB_1_reader = LimitedRandomReader(KB_1)
            client.put_object(bucket_name, path_prefix + object_name + '_' + str_i, KB_1_reader, KB_1)

        # List objects and check if 1001 files are returned
        list_objects_api_test(client, bucket_name, no_of_created_files)

    except Exception as err:
        raise Exception(err)
    finally:
        try:
            path_prefix = ''
            for i in range(no_of_created_files):
                str_i = str(i)
                client.remove_object(bucket_name, path_prefix + object_name + '_' + str_i)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_list_objects_v2(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        MB_1 = 1024*1024 # 1MiB.
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-1", MB_1_reader, MB_1)
        MB_1_reader = LimitedRandomReader(MB_1)
        client.put_object(bucket_name, object_name+"-2", MB_1_reader, MB_1)
        # List all object paths in bucket using V2 API.
        log_output.args['recursive'] = is_recursive = True
        objects = client.list_objects_v2(bucket_name, '', is_recursive)
        for obj in objects:
            _, _, _, _, _, _ = obj.bucket_name,\
                               obj.object_name,\
                               obj.last_modified,\
                               obj.etag, obj.size,\
                               obj.content_type
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name+"-1")
            client.remove_object(bucket_name, object_name+"-2")
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

# Helper method for test_list_incomplete_uploads
# and test_remove_incomplete_uploads tests
def create_upload_ids(client, b_name, o_name, n):
    # Create 'n' many incomplete upload ids and
    # return the list of created upload ids
    upload_ids_created = []
    for i in range(n):
        upload_id = client._new_multipart_upload(b_name, o_name, {})
        upload_ids_created.append(upload_id)
    return upload_ids_created

# Helper method for test_list_incomplete_uploads
# and test_remove_incomplete_uploads tests
def collect_incomplete_upload_ids(client, b_name, o_name):
    # Collect the upload ids from 'list_incomplete_uploads'
    # command, and return the list of created upload ids
    upload_ids_listed = []
    for obj in client.list_incomplete_uploads(b_name, o_name, False):
        upload_ids_listed.append(obj.upload_id)
    return upload_ids_listed

def test_remove_incomplete_upload(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_incomplete_upload(bucket_name, object_name)"

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        no_of_upload_ids = 3
        # Create 'no_of_upload_ids' many incomplete upload ids
        create_upload_ids(client, bucket_name, object_name, no_of_upload_ids)
        # Remove all of the created upload ids
        client.remove_incomplete_upload(bucket_name, object_name)
        # Get the list of incomplete upload ids for object_name
        # using 'list_incomplete_uploads' command
        upload_ids_listed = collect_incomplete_upload_ids(client,
                                                          bucket_name,
                                                          object_name)
        # Verify listed/returned upload id list
        if upload_ids_listed:
            # The list is not empty
            raise ValueError("There are still upload ids not removed")
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_presigned_get_object_default_expiry(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_get_object(bucket_name, object_name, expires, response_headers)"
    ca_certs = os.environ.get('SSL_CERT_FILE')
    if not ca_certs:
        ca_certs = certifi.where()

    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
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
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_presigned_get_object_expiry_5sec(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_get_object(bucket_name, object_name, expires, response_headers)"

    ca_certs = os.environ.get('SSL_CERT_FILE')
    if not ca_certs:
        ca_certs = certifi.where()
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_name, KB_1_reader, KB_1)

        presigned_get_object_url = client.presigned_get_object(bucket_name,
                                                               object_name,
                                                       timedelta(seconds=5))
        response = _http.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()
        # Wait for 5 seconds for the presigned url to expire
        time.sleep(5)
        response = _http.urlopen('GET', presigned_get_object_url)
        # Success with an expired url is considered to be a failure
        if response.status == 200:
            raise ValueError('Presigned get url failed to expire!')
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_presigned_get_object_response_headers(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_get_object(bucket_name, object_name, expires, response_headers)"

    ca_certs = os.environ.get('SSL_CERT_FILE')
    if not ca_certs:
        ca_certs = certifi.where()
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)
        KB_1 = 1024 # 1KiB.
        KB_1_reader = LimitedRandomReader(KB_1)
        client.put_object(bucket_name, object_name, KB_1_reader, KB_1)

        content_type = 'text/plain'
        content_language = 'en_US'
        response_headers = {'response-content-type': content_type,
                            'response-content-language': content_language}
        presigned_get_object_url = client.presigned_get_object(bucket_name,
                                                               object_name,
                                                      timedelta(seconds=5),
                                                          response_headers)
        response = _http.urlopen('GET', presigned_get_object_url)
        returned_content_type = response.headers['Content-Type']
        returned_content_language = response.headers['Content-Language']
        if response.status != 200 or returned_content_type != content_type or\
           returned_content_language != content_language:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_presigned_put_object_default_expiry(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_put_object(bucket_name, object_name, expires)"

    ca_certs = os.environ.get('SSL_CERT_FILE')
    if not ca_certs:
        ca_certs = certifi.where()
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        client.make_bucket(bucket_name)

        presigned_put_object_url = client.presigned_put_object(bucket_name,
                                                               object_name)
        MB_1 = 1024*1024 # 1MiB.
        response = _http.urlopen('PUT',
                                 presigned_put_object_url,
                                 LimitedRandomReader(MB_1))
        if response.status != 200:
            raise ResponseError(response,
                                'PUT',
                                bucket_name,
                                object_name).get_exception()
        client.stat_object(bucket_name, object_name)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_presigned_put_object_expiry_5sec(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_put_object(bucket_name, object_name, expires)"

    ca_certs = os.environ.get('SSL_CERT_FILE')
    if not ca_certs:
        ca_certs = certifi.where()
    _http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)

    # Get a unique bucket_name and object_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    KB_1 = 1024 # 1KiB.
    try:
        client.make_bucket(bucket_name)

        presigned_put_object_url = client.presigned_put_object(bucket_name,
                                                               object_name,
                                                       timedelta(seconds=5))
        # Wait for 5 seconds for the presigned url to expire
        time.sleep(5)
        response = _http.urlopen('PUT',
                                 presigned_put_object_url,
                                 LimitedRandomReader(KB_1))
        if response.status == 200:
            raise ValueError('Presigned put url failed to expire!')
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_presigned_post_policy(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_post_policy(post_policy)"

    bucket_name = generate_bucket_name()
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
        log_output.args['post_policy'] = {'bucket_name': bucket_name,
                                          'prefix': prefix,
                                          'expires_in_days': no_of_days}
        client.presigned_post_policy(policy)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_thread_safe(client, test_file, log_output):
    # Get a unique bucket_name and object_name
    no_of_threads = 5
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    log_output.args['object_name'] = object_name = uuid.uuid4().__str__()
    try:
        # Create sha-sum value for the user provided
        # source file, 'test_file'
        with open(test_file, 'rb') as f:
            contents = f.read()
            test_file_sha_sum = hashlib.sha256(contents).hexdigest()
        # Create the bucket
        client.make_bucket(bucket_name)
        # Put/Upload 'no_of_threads' many objects
        # simultaneously using multi-threading
        for i in range(no_of_threads):
            thrd = Thread(target=client.fput_object,
                          args=(bucket_name, object_name, test_file))
            thrd.start()
            thrd.join()

        # A list of exceptions raised by get_object_and_check
        # called in multiple threads.
        exceptions = []

        # get_object_and_check() downloads an object, stores it in a file
        # and then calculates its checksum. In case of mismatch, a new
        # exception is generated and saved in exceptions.
        def get_object_and_check(client, bckt_name, obj_name, no,
                expected_sha_sum):
            try:
                obj_data = client.get_object(bckt_name, obj_name)
                local_file = 'copied_file_'+str(no)
                # Create a file with the returned data
                with open(local_file, 'wb') as file_data:
                    shutil.copyfileobj(obj_data, file_data)
                with open(local_file, 'rb') as f:
                    contents = f.read()
                    copied_file_sha_sum = hashlib.sha256(contents).hexdigest()
                # Compare sha-sum values of the source file and the copied one
                if expected_sha_sum != copied_file_sha_sum:
                    raise ValueError(
                       'Sha-sum mismatch on multi-threaded put and get objects')
            except Exception as err:
                exceptions.append(Exception(err))
            finally:
                # Remove downloaded file
                os.path.isfile(local_file) and os.remove(local_file)

        # Get/Download 'no_of_threads' many objects
        # simultaneously using multi-threading
        thrd_list = []
        for i in range(no_of_threads):
            # Create dynamic/varying names for to be created threads
            thrd_name = 'thread_'+str(i)
            vars()[thrd_name] = Thread(target=get_object_and_check,
                                       args=(client, bucket_name,
                                       object_name, i, test_file_sha_sum))
            vars()[thrd_name].start()
            thrd_list.append(vars()[thrd_name])
        # Wait until all threads to finish
        for t in thrd_list:
            t.join()
        if len(exceptions) > 0:
            raise exceptions[0]
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_object(bucket_name, object_name)
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_get_bucket_policy(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "get_bucket_policy(bucket_name)"

    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    try:
        client.make_bucket(bucket_name)
        client.get_bucket_policy(bucket_name)
    except APINotImplemented:
        print(log_output.json_report(alert='Not Implemented', status=LogOutput.NA))
    except NoSuchBucketPolicy:
        # Test passes
        print(log_output.json_report())
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)

def get_policy_actions(stat):
    actions = []
    for s in stat:
        action = s.get('Action')
        if action not in actions:
            actions.append(action)
    # flatten  nested lists in actions
    flattened_actions = []
    for a in actions:
        if isinstance(a, list):
            for aa in a:
                flattened_actions.append(aa)
        else:
            flattened_actions.append(a)
    actions = [s.replace('s3:', '') for s in flattened_actions]
    return actions

def policy_validated(client, bucket_name, policy):
    policy_dict = json.loads(client.get_bucket_policy(bucket_name).decode("utf-8"))
    actions = get_policy_actions(policy_dict.get('Statement'))
    actions.sort()
    expected_actions = get_policy_actions(policy.get('Statement'))
    expected_actions.sort()
    if expected_actions != actions:
        return False
    return True

def test_get_bucket_notification(client, log_output):
    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    try:
        # make bucket as a preparation for empty bucket notification
        client.make_bucket(bucket_name)
        notification = client.get_bucket_notification(bucket_name)
        if notification != {}:
            raise ValueError("Failed to receive an empty bucket notification")

    except APINotImplemented:
            print(log_output.json_report(alert='Not Implemented',
                                         status=LogOutput.NA))
    except Exception as err:
            print("exception", err)
            raise Exception(err)
    else:
        # Test passes
        print(log_output.json_report())
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)


def test_set_bucket_policy_readonly(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "set_bucket_policy(bucket_name, policy)"

    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    try:
        client.make_bucket(bucket_name)
        # read-only policy
        policy = {
            "Version":"2012-10-17",
            "Statement":[
                {
                "Sid":"",
                "Effect":"Allow",
                "Principal":{"AWS":"*"},
                "Action":"s3:GetBucketLocation",
                "Resource":"arn:aws:s3:::"+bucket_name
                },
                {
                "Sid":"",
                "Effect":"Allow",
                "Principal":{"AWS":"*"},
                "Action":"s3:ListBucket",
                "Resource":"arn:aws:s3:::"+bucket_name
                },
                {
                "Sid":"",
                "Effect":"Allow",
                "Principal":{"AWS":"*"},
                "Action":"s3:GetObject",
                "Resource":"arn:aws:s3:::"+bucket_name+"/*"
                }
            ]
        }
        # Set read-only policy
        client.set_bucket_policy(bucket_name, json.dumps(policy))
        # Validate if the policy is set correctly
        if not policy_validated(client, bucket_name, policy):
            raise ValueError('Failed to set ReadOnly bucket policy')
    except APINotImplemented:
        print(log_output.json_report(alert='Not Implemented',
                                     status=LogOutput.NA))
    except Exception as err:
        raise Exception(err)
    else:
        # Test passes
        print(log_output.json_report())
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)

def test_set_bucket_policy_readwrite(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "set_bucket_policy(bucket_name, prefix, policy_access)"

    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    try:
        client.make_bucket(bucket_name)
        # Read-write policy
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["s3:GetBucketLocation"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::"+bucket_name],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                },
                {
                    "Action": ["s3:ListBucket"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::"+bucket_name],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                },
                {
                    "Action": ["s3:ListBucketMultipartUploads"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::"+bucket_name],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                },
                {
                    "Action": ["s3:ListMultipartUploadParts",
                               "s3:GetObject",
                               "s3:AbortMultipartUpload",
                               "s3:DeleteObject",
                               "s3:PutObject"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::"+bucket_name+"/*"],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                }
            ]
        }
        # Set read-write policy
        client.set_bucket_policy(bucket_name, json.dumps(policy))
        # Validate if the policy is set correctly
        if not policy_validated(client, bucket_name, policy):
            raise ValueError('Failed to set ReadOnly bucket policy')
    except APINotImplemented:
        print(log_output.json_report(alert='Not Implemented', status=LogOutput.NA))
    except Exception as err:
        raise Exception(err)
    else:
        # Test passes
        print(log_output.json_report())
    finally:
        try:
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)

def test_remove_objects(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_objects(bucket_name, objects_iter)"

    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    try:
        MB_1 = 1024*1024 # 1MiB.
        client.make_bucket(bucket_name)
        # Upload some new objects to prepare for multi-object delete test.
        object_names = []
        for i in range(10):
            curr_object_name = "prefix"+"-{}".format(i)
            client.put_object(bucket_name, curr_object_name, LimitedRandomReader(MB_1), MB_1)
            object_names.append(curr_object_name)
        log_output.args['objects_iter'] = objects_iter = object_names
        # delete the objects in a single library call.
        for del_err in client.remove_objects(bucket_name, objects_iter):
            raise ValueError("Remove objects err: {}".format(del_err))
    except Exception as err:
        raise Exception(err)
    finally:
        try:
           # Try to clean everything to keep our server intact
            for del_err in client.remove_objects(bucket_name, objects_iter):
                raise ValueError("Remove objects err: {}".format(del_err))
            client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())

def test_remove_bucket(client, log_output):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_bucket(bucket_name)"


    # Get a unique bucket_name
    log_output.args['bucket_name'] = bucket_name = generate_bucket_name()
    try:
        if is_s3(client):
            log_output.args['location'] = location = 'us-east-1'
            client.make_bucket(bucket_name+'.unique', location)
        else:
            client.make_bucket(bucket_name)
    except Exception as err:
        raise Exception(err)
    finally:
        try:
            # Removing bucket. This operation will only work if your bucket is empty.
            if is_s3(client):
                client.remove_bucket(bucket_name+'.unique')
            else:
                client.remove_bucket(bucket_name)
        except Exception as err:
            raise Exception(err)
    # Test passes
    print(log_output.json_report())


def isFullMode():
    return os.getenv("MINT_MODE") == "full"


def main():
    """
    Functional testing of minio python library.
    """

    try:
        access_key = os.getenv('ACCESS_KEY', 'Q3AM3UQ867SPQQA43P2F')
        secret_key = os.getenv('SECRET_KEY',
                               'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
        server_endpoint = os.getenv('SERVER_ENDPOINT', 'play.min.io:9000')
        secure = os.getenv('ENABLE_HTTPS', '1') == '1'
        if server_endpoint == 'play.min.io:9000':
            access_key = 'Q3AM3UQ867SPQQA43P2F'
            secret_key = 'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG'
            secure = True

        client = Minio(server_endpoint, access_key, secret_key, secure=secure)
        # Check if we are running in the mint environment.
        data_dir = os.getenv('DATA_DIR')
        if data_dir is None:
            os.environ['DATA_DIR'] = data_dir = '/mint/data'

        is_mint_env = (os.path.exists(data_dir) and
                       os.path.exists(os.path.join(data_dir, 'datafile-1-MB')) and
                       os.path.exists(os.path.join(data_dir, 'datafile-11-MB')))

        # Enable trace
        # import sys
        # client.trace_on(sys.stderr)

        testfile = 'datafile-1-MB'
        largefile = 'datafile-11-MB'
        if is_mint_env:
            # Choose data files
            testfile = os.path.join(data_dir, 'datafile-1-MB')
            largefile = os.path.join(data_dir, 'datafile-11-MB')
        else:
            with open(testfile, 'wb') as file_data:
                shutil.copyfileobj(LimitedRandomReader(1024*1024), file_data)
            with open(largefile, 'wb') as file_data:
                shutil.copyfileobj(LimitedRandomReader(11*1024*1024), file_data)

        # Create a Customer Key of 32 Bytes for Server Side Encryption (SSE-C)
        cust_key = b'AABBCCDDAABBCCDDAABBCCDDAABBCCDD'
        # Create an SSE-C object with provided customer key
        ssec = SSE_C(cust_key)
        # Test copy_object for SSE-C
        ssec_copy = copy_SSE_C(cust_key)

        if isFullMode():
            log_output =  LogOutput(client.make_bucket, 'test_make_bucket_default_region')
            test_make_bucket_default_region(client, log_output)

            log_output =  LogOutput(client.make_bucket, 'test_make_bucket_with_region')
            test_make_bucket_with_region(client, log_output)

            log_output =  LogOutput(client.make_bucket, 'test_negative_make_bucket_invalid_name')
            test_negative_make_bucket_invalid_name(client, log_output)

            log_output =  LogOutput(client.list_buckets, 'test_list_buckets')
            test_list_buckets(client, log_output)

            log_output =  LogOutput(client.fput_object, 'test_fput_object_small_file')
            test_fput_object_small_file(client, testfile, log_output)

            if secure:
                log_output = LogOutput(client.fput_object, 'test_fput_object_small_file_with_SSE-C')
                test_fput_object_small_file(client, testfile, log_output, sse=ssec)

            log_output =  LogOutput(client.fput_object, 'test_fput_object_large_file')
            test_fput_object_large_file(client, largefile, log_output)

            if secure:
                log_output = LogOutput(client.fput_object, 'test_fput_object_large_file_with_SSE-C')
                test_fput_object_large_file(client, largefile, log_output, sse=ssec)

            log_output =  LogOutput(client.fput_object, 'test_fput_object_with_content_type')
            test_fput_object_with_content_type(client, testfile, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_no_copy_condition')
            test_copy_object_no_copy_condition(client, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_etag_match')
            test_copy_object_etag_match(client, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_with_metadata')
            test_copy_object_with_metadata(client, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_negative_etag_match')
            test_copy_object_negative_etag_match(client, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_modified_since')
            test_copy_object_modified_since(client, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_unmodified_since')
            test_copy_object_unmodified_since(client, log_output)

            if secure:
                log_output = LogOutput(client.copy_object, 'test_copy_object_with_sse')
                test_copy_object_no_copy_condition(client, log_output, ssec_copy=ssec_copy, ssec=ssec)

            log_output =  LogOutput(client.put_object, 'test_put_object')
            test_put_object(client, log_output)

            if secure:
                log_output = LogOutput(client.put_object, 'test_put_object_with_SSE-C')
                test_put_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.put_object, 'test_negative_put_object_with_path_segment')
            test_negative_put_object_with_path_segment(client, log_output)

            log_output =  LogOutput(client.stat_object, 'test_stat_object')
            test_stat_object(client, log_output)

            if secure:
                log_output = LogOutput(client.stat_object, 'test_stat_object_with_SSE-C')
                test_stat_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.get_object, 'test_get_object')
            test_get_object(client, log_output)

            if secure:
                log_output = LogOutput(client.get_object, 'test_get_object_with_SSE-C')
                test_get_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.fget_object, 'test_fget_object')
            test_fget_object(client, log_output)

            if secure:
                log_output = LogOutput(client.fget_object, 'test_fget_object_with_SSE-C')
                test_fget_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.get_partial_object, 'test_get_partial_object_with_default_length')
            test_get_partial_object_with_default_length(client, log_output)

            log_output =  LogOutput(client.get_partial_object, 'test_get_partial_object')
            test_get_partial_object(client, log_output)

            if secure:
                log_output = LogOutput(client.get_partial_object, 'test_get_partial_object_with_SSE-C')
                test_get_partial_object(client, log_output)

            log_output =  LogOutput(client.list_objects, 'test_list_objects')
            test_list_objects(client, log_output)

            log_output =  LogOutput(client.list_objects, 'test_list_objects_with_prefix')
            test_list_objects_with_prefix(client, log_output)

            log_output =  LogOutput(client.list_objects, 'test_list_objects_with_1001_files')
            test_list_objects_with_1001_files(client, log_output)

            log_output =  LogOutput(client.remove_incomplete_upload, 'test_remove_incomplete_upload')
            test_remove_incomplete_upload(client, log_output)

            log_output =  LogOutput(client.list_objects_v2, 'test_list_objects_v2')
            test_list_objects_v2(client, log_output)

            log_output =  LogOutput(client.presigned_get_object, 'test_presigned_get_object_default_expiry')
            test_presigned_get_object_default_expiry(client, log_output)

            log_output =  LogOutput(client.presigned_get_object, 'test_presigned_get_object_expiry_5sec')
            test_presigned_get_object_expiry_5sec(client, log_output)

            log_output =  LogOutput(client.presigned_get_object, 'test_presigned_get_object_response_headers')
            test_presigned_get_object_response_headers(client, log_output)

            log_output =  LogOutput(client.presigned_put_object, 'test_presigned_put_object_default_expiry')
            test_presigned_put_object_default_expiry(client, log_output)

            log_output =  LogOutput(client.presigned_put_object, 'test_presigned_put_object_expiry_5sec')
            test_presigned_put_object_expiry_5sec(client, log_output)

            log_output =  LogOutput(client.presigned_post_policy, 'test_presigned_post_policy')
            test_presigned_post_policy(client, log_output)

            log_output =  LogOutput(client.put_object, 'test_thread_safe')
            test_thread_safe(client, testfile, log_output)

            log_output =  LogOutput(client.get_bucket_policy, 'test_get_bucket_policy')
            test_get_bucket_policy(client, log_output)

            log_output =  LogOutput(client.set_bucket_policy, 'test_set_bucket_policy_readonly')
            test_set_bucket_policy_readonly(client, log_output)

            log_output =  LogOutput(client.set_bucket_policy, 'test_set_bucket_policy_readwrite')
            test_set_bucket_policy_readwrite(client, log_output)

            log_output = LogOutput(client.get_bucket_notification, 'test_get_bucket_notification')
            test_get_bucket_notification(client, log_output)

        else:
            # Quick mode tests
            log_output =  LogOutput(client.make_bucket, 'test_make_bucket_default_region')
            test_make_bucket_default_region(client, log_output)

            log_output =  LogOutput(client.list_buckets, 'test_list_buckets')
            test_list_buckets(client, log_output)

            log_output =  LogOutput(client.put_object, 'test_put_object')
            test_put_object(client, log_output)

            if secure:
                log_output =  LogOutput(client.put_object, 'test_put_object_with_SSE-C')
                test_put_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.stat_object, 'test_stat_object')
            test_stat_object(client, log_output)

            if secure:
                log_output = LogOutput(client.stat_object, 'test_stat_object_with_SSE-C')
                test_stat_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.get_object, 'test_get_object')
            test_get_object(client, log_output)

            if secure:
                log_output = LogOutput(client.get_object, 'test_get_object_with_SSE-C')
                test_get_object(client, log_output, sse=ssec)

            log_output =  LogOutput(client.list_objects, 'test_list_objects')
            test_list_objects(client, log_output)

            log_output =  LogOutput(client.remove_incomplete_upload, 'test_remove_incomplete_upload')
            test_remove_incomplete_upload(client, log_output)

            log_output =  LogOutput(client.presigned_get_object, 'test_presigned_get_object_default_expiry')
            test_presigned_get_object_default_expiry(client, log_output)

            log_output =  LogOutput(client.presigned_put_object, 'test_presigned_put_object_default_expiry')
            test_presigned_put_object_default_expiry(client, log_output)

            log_output =  LogOutput(client.presigned_post_policy, 'test_presigned_post_policy')
            test_presigned_post_policy(client, log_output)

            log_output =  LogOutput(client.copy_object, 'test_copy_object_no_copy_condition')
            test_copy_object_no_copy_condition(client, log_output)

            if secure:
                log_output = LogOutput(client.copy_object, 'test_copy_object_with_sse')
                test_copy_object_no_copy_condition(client, log_output, ssec_copy=ssec_copy, ssec=ssec)

            log_output =  LogOutput(client.get_bucket_policy, 'test_get_bucket_policy')
            test_get_bucket_policy(client, log_output)

            log_output =  LogOutput(client.set_bucket_policy, 'test_set_bucket_policy_readonly')
            test_set_bucket_policy_readonly(client, log_output)

            log_output = LogOutput(client.get_bucket_notification, 'test_get_bucket_notification')
            test_get_bucket_notification(client, log_output)


        # Remove all objects.
        log_output =  LogOutput(client.remove_object, 'test_remove_object')
        test_remove_object(client, log_output)

        log_output =  LogOutput(client.remove_objects, 'test_remove_objects')
        test_remove_objects(client, log_output)

        log_output =  LogOutput(client.remove_bucket, 'test_remove_bucket')
        test_remove_bucket(client, log_output)

        # Remove temporary files.
        if not is_mint_env:
            os.remove(testfile)
            os.remove(largefile)
    except Exception as err:
        print(log_output.json_report(err))
        exit(1)

if __name__ == "__main__":
    # Execute only if run as a script
    main()
