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

from __future__ import absolute_import, division

import hashlib
import io
import json
import math
import os
import random
import shutil
import string
import sys
import tempfile
import time
import traceback
from datetime import datetime, timedelta
from inspect import getargspec
from threading import Thread
from uuid import uuid4

import certifi
import urllib3

from minio import CopyConditions, Minio, PostPolicy
from minio.error import (APINotImplemented, InvalidBucketError,
                         NoSuchBucketPolicy, PreconditionFailed, ResponseError)
from minio.select.helpers import calculate_crc
from minio.select.options import (CSVInput, CSVOutput, InputSerialization,
                                  OutputSerialization, RequestProgress,
                                  SelectObjectOptions)
from minio.sse import SSE_C, copy_SSE_C

if sys.version_info[0] == 2:
    from datetime import tzinfo

    class UTC(tzinfo):
        """UTC"""

        def utcoffset(self, dt):
            return timedelta(0)

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return timedelta(0)

    utc = UTC()
else:
    from datetime import timezone
    utc = timezone.utc
    from inspect import getfullargspec
    getargspec = getfullargspec

global client, testfile, largefile
KB = 1024
MB = 1024 * KB
http = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs=os.environ.get('SSL_CERT_FILE') or certifi.where()
)


def generate_bucket_name():
    return "minio-py-test-{0}".format(uuid4())


def is_s3():
    return ".amazonaws.com" in client._endpoint_url


def isFullMode():
    return os.getenv("MINT_MODE") == "full"


def normalize_metadata(metadata):
    return {k.lower(): v for k, v in metadata.items()}


def _get_sha256sum(filename):
    with open(filename, 'rb') as f:
        contents = f.read()
        return hashlib.sha256(contents).hexdigest()


def _get_random_string(size):
    if not size:
        return ""

    chars = string.ascii_lowercase
    chars *= int(math.ceil(size / len(chars)))
    chars = list(chars[:size])
    random.shuffle(chars)
    return "".join(chars)


class LimitedRandomReader(object):
    def __init__(self, limit):
        self._limit = limit

    def read(self, size=64*KB):
        if size < 0 or size > self._limit:
            size = self._limit

        s = _get_random_string(size)
        self._limit -= size
        return s.encode()


def call(log_entry, func, *args, **kwargs):
    log_entry["method"] = func
    return func(*args, **kwargs)


class TestFailedException(Exception):
    pass


def testit(func, *args, **kwargs):
    log_entry = {
        "name": func.__name__,
        "status": "PASS",
    }

    start_time = time.time()
    try:
        func(log_entry, *args, **kwargs)
    except APINotImplemented:
        log_entry["alert"] = "Not Implemented"
        log_entry["status"] = "NA"
    except Exception as e:
        log_entry["message"] = "{0}".format(e)
        log_entry["error"] = traceback.format_exc()
        log_entry["status"] = "FAIL"

    if log_entry.get("method"):
        log_entry["function"] = "{0}({1})".format(
            log_entry["method"].__name__,
            ', '.join(getargspec(log_entry["method"]).args[1:]))
    log_entry["args"] = {
        k: v for k, v in log_entry.get("args", {}).items() if v
    }
    log_entry["duration"] = int(
        round((time.time() - start_time) * 1000))
    log_entry["name"] = 'minio-py:' + log_entry["name"]
    log_entry["method"] = None
    print(json.dumps({k: v for k, v in log_entry.items() if v}))
    if log_entry["status"] == "FAIL":
        raise TestFailedException()


def test_make_bucket_default_region(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "make_bucket(bucket_name, location)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "location": "default value ('us-east-1')",  # Default location
    }

    # Create a bucket with default bucket location
    call(log_entry, client.make_bucket, bucket_name)
    # Check if bucket was created properly
    call(log_entry, client.bucket_exists, bucket_name)
    # Remove bucket
    call(log_entry, client.remove_bucket, bucket_name)
    # Test passes
    log_entry["method"] = client.make_bucket


def test_make_bucket_with_region(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "make_bucket(bucket_name, location)"

    # Only test make bucket with region against AWS S3
    if not is_s3():
        return

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    # A non-default location
    location = 'us-west-1'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "location": location,
    }

    # Create a bucket with default bucket location
    call(log_entry, client.make_bucket, bucket_name, location)
    # Check if bucket was created properly
    call(log_entry, client.bucket_exists, bucket_name)
    # Remove bucket
    call(log_entry, client.remove_bucket, bucket_name)
    # Test passes
    log_entry["method"] = client.make_bucket


def test_negative_make_bucket_invalid_name(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "make_bucket(bucket_name, location)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    # Default location
    log_entry["args"] = {
        "location": "default value ('us-east-1')",
    }
    # Create an array of invalid bucket names to test
    invalid_bucket_name_list = [
        bucket_name + '.',
        '.' + bucket_name,
        bucket_name + '...abcd'
    ]
    for name in invalid_bucket_name_list:
        log_entry["args"]["bucket_name"] = name
        try:
            # Create a bucket with default bucket location
            call(log_entry, client.make_bucket, bucket_name)
            # Check if bucket was created properly
            call(log_entry, client.bucket_exists, bucket_name)
            # Remove bucket
            call(log_entry, client.remove_bucket, bucket_name)
        except InvalidBucketError:
            pass
    # Test passes
    log_entry["method"] = client.make_bucket
    log_entry["args"]['bucket_name'] = invalid_bucket_name_list


def test_list_buckets(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "list_buckets(  )"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()

    # Create a bucket with default bucket location
    call(log_entry, client.make_bucket, bucket_name)

    try:
        buckets = client.list_buckets()
        for bucket in buckets:
            # bucket object should be of a valid value.
            if bucket.name and bucket.creation_date:
                continue
            raise ValueError('list_bucket api failure')
    finally:
        # Remove bucket
        call(log_entry, client.remove_bucket, bucket_name)


def test_select_object_content(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "client.select_object_content(bucket_name, object_name, options)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    csvfile = 'test.csv'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": csvfile,
    }

    try:
        client.make_bucket(bucket_name)
        content = io.BytesIO(b"col1,col2,col3\none,two,three\nX,Y,Z\n")
        client.put_object(bucket_name, csvfile, content,
                          len(content.getvalue()))

        options = SelectObjectOptions(
            expression="select * from s3object",
            input_serialization=InputSerialization(
                compression_type="NONE",
                csv=CSVInput(FileHeaderInfo="NONE",
                             RecordDelimiter="\n",
                             FieldDelimiter=",",
                             QuoteCharacter='"',
                             QuoteEscapeCharacter='"',
                             Comments="#",
                             AllowQuotedRecordDelimiter="FALSE")
            ),
            output_serialization=OutputSerialization(
                csv=CSVOutput(QuoteFields="ASNEEDED",
                              RecordDelimiter="\n",
                              FieldDelimiter=",",
                              QuoteCharacter='"',
                              QuoteEscapeCharacter='"')
            ),
            request_progress=RequestProgress(enabled="False")
        )

        data = client.select_object_content(bucket_name, csvfile, options)
        # Get the records
        records = io.BytesIO()
        for d in data.stream(10*KB):
            records.write(d.encode('utf-8'))

        expected_crc = calculate_crc(content.getvalue())
        generated_crc = calculate_crc(records.getvalue())
        if expected_crc != generated_crc:
            raise ValueError(
                'Data mismatch Expected : '
                '"col1,col2,col3\none,two,three\nX,Y,Z\n"',
                'Received {}', records)
    finally:
        client.remove_object(bucket_name, csvfile)
        client.remove_bucket(bucket_name)


def fput_object_test(bucket_name, object_name, filename, metadata, sse):
    try:
        client.make_bucket(bucket_name)
        if is_s3():
            client.fput_object(bucket_name, object_name, filename,
                               metadata=metadata, sse=sse)
        else:
            client.fput_object(bucket_name, object_name, filename, sse=sse)

        client.stat_object(bucket_name, object_name, sse=sse)
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_fput_object_small_file(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "fput_object(bucket_name, object_name, file_path, "
    #     "content_type, metadata)"

    if sse:
        log_entry["name"] += "_with_SSE-C"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}-f".format(uuid4())
    metadata = {'x-amz-storage-class': 'STANDARD_IA'}

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": testfile,
        "metadata": metadata,
    }

    fput_object_test(bucket_name, object_name, testfile, metadata, sse)


def test_fput_object_large_file(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "fput_object(bucket_name, object_name, file_path, "
    #     "content_type, metadata)"

    if sse:
        log_entry["name"] += "_with_SSE-C"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}-large".format(uuid4())
    metadata = {'x-amz-storage-class': 'STANDARD_IA'}

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": largefile,
        "metadata": metadata,
    }

    # upload local large file through multipart.
    fput_object_test(bucket_name, object_name, largefile, metadata, sse)


def test_fput_object_with_content_type(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "fput_object(bucket_name, object_name, file_path, "
    #     "content_type, metadata)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}-f".format(uuid4())
    metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    content_type = 'application/octet-stream'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": testfile,
        "metadata": metadata,
        "content_type": content_type,
    }

    fput_object_test(bucket_name, object_name, testfile, metadata, None)


def test_copy_object_no_copy_condition(log_entry, ssec_copy=None, ssec=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "copy_object(bucket_name, object_name, object_source, conditions)"

    if ssec_copy or ssec:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        client.put_object(bucket_name, object_source, reader, size, sse=ssec)
        client.copy_object(bucket_name, object_copy,
                           '/' + bucket_name + '/' + object_source,
                           source_sse=ssec_copy, sse=ssec)
        st_obj = client.stat_object(bucket_name, object_copy, sse=ssec)
        validate_stat_data(st_obj, size, {})
    finally:
        client.remove_object(bucket_name, object_source)
        client.remove_object(bucket_name, object_copy)
        client.remove_bucket(bucket_name)


def test_copy_object_with_metadata(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "copy_object(bucket_name, object_name, object_source, metadata)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"
    metadata = {"testing-string": "string",
                "testing-int": 1}

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
        "metadata": metadata,
    }

    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        client.put_object(bucket_name, object_source, reader, size)
        # Perform a server side copy of an object
        client.copy_object(bucket_name, object_copy,
                           '/' + bucket_name + '/' + object_source,
                           metadata=metadata)
        # Verification
        st_obj = client.stat_object(bucket_name, object_copy)
        expected_metadata = {'x-amz-meta-testing-int': '1',
                             'x-amz-meta-testing-string': 'string'}
        validate_stat_data(st_obj, size, expected_metadata)
    finally:
        client.remove_object(bucket_name, object_source)
        client.remove_object(bucket_name, object_copy)
        client.remove_bucket(bucket_name)


def test_copy_object_etag_match(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        client.put_object(bucket_name, object_source, reader, size)
        # Perform a server side copy of an object
        client.copy_object(bucket_name, object_copy,
                           '/' + bucket_name + '/' + object_source)
        # Verification
        source_etag = client.stat_object(bucket_name, object_source).etag
        copy_conditions = CopyConditions()
        copy_conditions.set_match_etag(source_etag)
        log_entry["args"]["conditions"] = {'set_match_etag': source_etag}
        client.copy_object(bucket_name, object_copy,
                           '/' + bucket_name + '/' + object_source,
                           copy_conditions)
    finally:
        client.remove_object(bucket_name, object_source)
        client.remove_object(bucket_name, object_copy)
        client.remove_bucket(bucket_name)


def test_copy_object_negative_etag_match(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        client.put_object(bucket_name, object_source, reader, size)
        try:
            # Perform a server side copy of an object
            # with incorrect pre-conditions and fail
            etag = 'test-etag'
            copy_conditions = CopyConditions()
            copy_conditions.set_match_etag(etag)
            log_entry["args"]["conditions"] = {'set_match_etag': etag}
            client.copy_object(bucket_name, object_copy,
                               '/' + bucket_name + '/' + object_source,
                               copy_conditions)
        except PreconditionFailed as e:
            if e.message != (
                    "At least one of the preconditions you specified "
                    "did not hold."):
                raise
    finally:
        client.remove_object(bucket_name, object_source)
        client.remove_object(bucket_name, object_copy)
        client.remove_bucket(bucket_name)


def test_copy_object_modified_since(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        client.put_object(bucket_name, object_source, reader, size)
        # Set up the 'modified_since' copy condition
        copy_conditions = CopyConditions()
        mod_since = datetime(2014, 4, 1, tzinfo=utc)
        copy_conditions.set_modified_since(mod_since)
        log_entry["args"]["conditions"] = {
            'set_modified_since': mod_since.strftime('%c')}
        # Perform a server side copy of an object
        # and expect the copy to complete successfully
        client.copy_object(bucket_name, object_copy,
                           '/' + bucket_name + '/' + object_source,
                           copy_conditions)
    finally:
        client.remove_object(bucket_name, object_source)
        client.remove_object(bucket_name, object_copy)
        client.remove_bucket(bucket_name)


def test_copy_object_unmodified_since(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "copy_object(bucket_name, object_name, object_source, conditions)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        client.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        client.put_object(bucket_name, object_source, reader, size)
        # Set up the 'unmodified_since' copy condition
        copy_conditions = CopyConditions()
        unmod_since = datetime(2014, 4, 1, tzinfo=utc)
        copy_conditions.set_unmodified_since(unmod_since)
        log_entry["args"]["conditions"] = {
            'set_unmodified_since': unmod_since.strftime('%c')}
        try:
            # Perform a server side copy of an object and expect
            # the copy to fail since the creation/modification
            # time is now, way later than unmodification time, April 1st, 2014
            client.copy_object(bucket_name, object_copy,
                               '/' + bucket_name + '/' + object_source,
                               copy_conditions)
        except PreconditionFailed as e:
            if e.message != (
                    "At least one of the preconditions you specified "
                    "did not hold."):
                raise
    finally:
        client.remove_object(bucket_name, object_source)
        client.remove_object(bucket_name, object_copy)
        client.remove_bucket(bucket_name)


def test_put_object(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "put_object(bucket_name, object_name, data, length, content_type,"
    #     "metadata)"

    if sse:
        log_entry["name"] += "_SSE"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "length": length,
        "data": "LimitedRandomReader(1 * MB)"
    }

    try:
        client.make_bucket(bucket_name)
        # Put/Upload a streaming object of 1 MiB
        reader = LimitedRandomReader(length)
        client.put_object(bucket_name, object_name, reader, length, sse=sse)
        client.stat_object(bucket_name, object_name, sse=sse)

        # Put/Upload a streaming object of 11 MiB
        log_entry["args"]["length"] = length = 11 * MB
        reader = LimitedRandomReader(length)
        log_entry["args"]["data"] = "LimitedRandomReader(11 * MB)"
        log_entry["args"]["metadata"] = metadata = {
            'x-amz-meta-testing': 'value', 'test-key': 'value2'}
        log_entry["args"]["content_type"] = content_type = (
            "application/octet-stream")
        log_entry["args"]["object_name"] = object_name + "-metadata"
        client.put_object(bucket_name, object_name + "-metadata", reader,
                          length, content_type, metadata, sse=sse)
        # Stat on the uploaded object to check if it exists
        # Fetch saved stat metadata on a previously uploaded object with
        # metadata.
        st_obj = client.stat_object(bucket_name, object_name + "-metadata",
                                    sse=sse)
        normalized_meta = normalize_metadata(st_obj.metadata)
        if 'x-amz-meta-testing' not in normalized_meta:
            raise ValueError("Metadata key 'x-amz-meta-testing' not found")
        value = normalized_meta['x-amz-meta-testing']
        if value != 'value':
            raise ValueError('Metadata key has unexpected'
                             ' value {0}'.format(value))
        if 'x-amz-meta-test-key' not in normalized_meta:
            raise ValueError("Metadata key 'x-amz-meta-test-key' not found")
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_object(bucket_name, object_name+'-metadata')
        client.remove_bucket(bucket_name)


def test_negative_put_object_with_path_segment(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "put_object(bucket_name, object_name, data, length, content_type,"
    #     "metadata)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "/a/b/c/{0}".format(uuid4())
    length = 0

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "length": length,
        "data": "",
    }

    try:
        client.make_bucket(bucket_name)
        client.put_object(bucket_name, object_name, io.BytesIO(b''), 0)
        client.remove_object(bucket_name, object_name)
    except ResponseError as err:
        if err.code != 'XMinioInvalidObjectName':
            raise
    finally:
        client.remove_bucket(bucket_name)


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

    if not received_etag:
        raise ValueError('No Etag value is returned.')

    # content_type by default can be either application/octet-stream or
    # binary/octet-stream
    if received_content_type not in [
            'application/octet-stream', 'binary/octet-stream']:
        raise ValueError('Incorrect content type. Expected: ',
                         "'application/octet-stream' or 'binary/octet-stream',"
                         " received: ", received_content_type)

    if received_size != expected_size:
        raise ValueError('Incorrect file size. Expected: 11534336',
                         ', received: ', received_size)

    if received_is_dir:
        raise ValueError('Incorrect file type. Expected: is_dir=False',
                         ', received: is_dir=', received_is_dir)

    if not all(i in received_metadata.items() for i in expected_meta.items()):
        raise ValueError("Metadata key 'x-amz-meta-testing' not found")


def test_stat_object(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function = "stat_object(bucket_name, object_name)"

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "length": length,
        "data": "LimitedRandomReader(1 * MB)"
    }

    try:
        client.make_bucket(bucket_name)
        # Put/Upload a streaming object of 1 MiB
        reader = LimitedRandomReader(length)
        client.put_object(bucket_name, object_name, reader, length, sse=sse)
        client.stat_object(bucket_name, object_name, sse=sse)

        # Put/Upload a streaming object of 11 MiB
        log_entry["args"]["length"] = length = 11 * MB
        reader = LimitedRandomReader(length)
        log_entry["args"]["data"] = "LimitedRandomReader(11 * MB)"
        log_entry["args"]["metadata"] = metadata = {
            'X-Amz-Meta-Testing': 'value'}
        log_entry["args"]["content_type"] = content_type = (
            "application/octet-stream")
        log_entry["args"]["object_name"] = object_name + "-metadata"
        client.put_object(bucket_name, object_name + "-metadata", reader,
                          length, content_type, metadata, sse=sse)
        # Stat on the uploaded object to check if it exists
        # Fetch saved stat metadata on a previously uploaded object with
        # metadata.
        st_obj = client.stat_object(bucket_name, object_name + "-metadata",
                                    sse=sse)
        # Verify the collected stat data.
        validate_stat_data(st_obj, length, normalize_metadata(metadata))
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_object(bucket_name, object_name+'-metadata')
        client.remove_bucket(bucket_name)


def test_remove_object(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_object(bucket_name, object_name)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * KB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        client.put_object(bucket_name, object_name,
                          LimitedRandomReader(length), length)
        client.remove_object(bucket_name, object_name)
    finally:
        client.remove_bucket(bucket_name)


def test_get_object(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "get_object(bucket_name, object_name, request_headers)"

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        client.put_object(bucket_name, object_name,
                          LimitedRandomReader(length), length, sse=sse)
        # Get/Download a full object, iterate on response to save to disk
        object_data = client.get_object(bucket_name, object_name, sse=sse)
        newfile = 'newfile جديد'
        with open(newfile, 'wb') as file_data:
            shutil.copyfileobj(object_data, file_data)
        os.remove(newfile)
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_fget_object(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "fget_object(bucket_name, object_name, file_path, request_headers)"

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    tmpfd, tmpfile = tempfile.mkstemp()
    os.close(tmpfd)
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": tmpfile
    }

    client.make_bucket(bucket_name)
    try:
        client.put_object(bucket_name, object_name,
                          LimitedRandomReader(length), length, sse=sse)
        # Get/Download a full object and save locally at path
        client.fget_object(bucket_name, object_name, tmpfile, sse=sse)
        os.remove(tmpfile)
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_get_partial_object_with_default_length(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "get_partial_object(bucket_name, object_name, offset, length,"
    #     "request_headers)"

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    size = 1 * MB
    length = 1000
    offset = size - length

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "offset": offset
    }

    client.make_bucket(bucket_name)
    try:
        client.put_object(bucket_name, object_name,
                          LimitedRandomReader(size), size, sse=sse)
        # Get half of the object
        object_data = client.get_partial_object(bucket_name, object_name,
                                                offset, sse=sse)
        newfile = 'newfile'
        with open(newfile, 'wb') as file_data:
            for d in object_data:
                file_data.write(d)
        # Check if the new file is the right size
        new_file_size = os.path.getsize(newfile)
        os.remove(newfile)
        if new_file_size != length:
            raise ValueError('Unexpected file size after running ')
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_get_partial_object(log_entry, sse=None):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "get_partial_object(bucket_name, object_name, offset, length,"
    #     "request_headers)"

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    size = 1 * MB
    offset = int(size / 2)
    length = offset - 1000

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "offset": offset
    }

    client.make_bucket(bucket_name)
    try:
        client.put_object(bucket_name, object_name,
                          LimitedRandomReader(size), size, sse=sse)
        # Get half of the object
        object_data = client.get_partial_object(bucket_name, object_name,
                                                offset, length, sse=sse)
        newfile = 'newfile'
        with open(newfile, 'wb') as file_data:
            for d in object_data:
                file_data.write(d)
        # Check if the new file is the right size
        new_file_size = os.path.getsize(newfile)
        os.remove(newfile)
        if new_file_size != length:
            raise ValueError('Unexpected file size after running ')
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_list_objects(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    is_recursive = True

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "recursive": is_recursive,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        client.put_object(bucket_name, object_name + "-1",
                          LimitedRandomReader(size), size)
        client.put_object(bucket_name, object_name + "-2",
                          LimitedRandomReader(size), size)
        # List all object paths in bucket.
        objects = client.list_objects(bucket_name, '', is_recursive)
        for obj in objects:
            _ = (obj.bucket_name, obj.object_name, obj.last_modified,
                 obj.etag, obj.size, obj.content_type)
    finally:
        client.remove_object(bucket_name, object_name + "-1")
        client.remove_object(bucket_name, object_name + "-2")
        client.remove_bucket(bucket_name)


def list_objects_api_test(bucket_name, expected_no, *argv):
    # argv is composed of prefix and recursive arguments of
    # list_objects api. They are both supposed to be passed as strings.
    objects = client.list_objects(bucket_name, *argv)

    # expect all objects to be listed
    no_of_files = 0
    for obj in objects:
        _ = (obj.bucket_name, obj.object_name, obj.last_modified, obj.etag,
             obj.size, obj.content_type)
        no_of_files += 1

    if expected_no != no_of_files:
        raise ValueError(
            ("Listed no of objects ({}), does not match the "
             "expected no of objects ({})").format(no_of_files, expected_no))


def test_list_objects_with_prefix(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        no_of_created_files = 4
        path_prefix = ""
        # Create files and directories
        for i in range(no_of_created_files):
            client.put_object(bucket_name,
                              "{0}{1}_{2}".format(path_prefix, i, object_name),
                              LimitedRandomReader(size), size)
            path_prefix = "{0}{1}/".format(path_prefix, i)

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
        log_entry["args"]["prefix"] = prefix = ""  # no prefix
        log_entry["args"]["recursive"] = recursive = ""
        list_objects_api_test(bucket_name, no_of_created_files, prefix, True)

        # List objects at the top level with no prefix and no recursive option
        # Expect only the top 2 objects to be listed
        list_objects_api_test(bucket_name, 2)

        # List objects for '0' directory/prefix without recursive option
        # Expect 2 object (directory '0' and '0_' object) to be listed
        log_entry["args"]["prefix"] = prefix = "0"
        list_objects_api_test(bucket_name, 2, prefix)

        # List objects for '0/' directory/prefix without recursive option
        # Expect only 2 objects under directory '0/' to be listed,
        # non-recursive
        log_entry["args"]["prefix"] = prefix = "0/"
        list_objects_api_test(bucket_name, 2, prefix)

        # List objects for '0/' directory/prefix, recursively
        # Expect 2 objects to be listed
        log_entry["args"]["prefix"] = prefix = "0/"
        log_entry["args"]["recursive"] = recursive = "True"
        list_objects_api_test(bucket_name, 3, prefix, recursive)

        # List object with '0/1/2/' directory/prefix, non-recursive
        # Expect the single object under directory '0/1/2/' to be listed
        log_entry["args"]["prefix"] = prefix = "0/1/2/"
        list_objects_api_test(bucket_name, 1, prefix)
    finally:
        path_prefix = ""
        for i in range(no_of_created_files):
            client.remove_object(
                bucket_name,
                "{0}{1}_{2}".format(path_prefix, i, object_name))
            path_prefix = "{0}{1}/".format(path_prefix, i)
        client.remove_bucket(bucket_name)
    # Test passes
    log_entry["args"]["prefix"] = (
        "Several prefix/recursive combinations are tested")
    log_entry["args"]["recursive"] = (
        'Several prefix/recursive combinations are tested')


def test_list_objects_with_1001_files(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": "{0}_0 ~ {0}_1000".format(object_name),
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        no_of_created_files = 2000
        # Create files and directories
        for i in range(no_of_created_files):
            client.put_object(bucket_name,
                              "{0}_{1}".format(object_name, i),
                              LimitedRandomReader(size), size)

        # List objects and check if 1001 files are returned
        list_objects_api_test(bucket_name, no_of_created_files)
    finally:
        for i in range(no_of_created_files):
            client.remove_object(bucket_name,
                                 "{0}_{1}".format(object_name, i))
        client.remove_bucket(bucket_name)


def test_list_objects_v2(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "list_objects(bucket_name, prefix, recursive)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    is_recursive = True

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "recursive": is_recursive,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        client.put_object(bucket_name, object_name + "-1",
                          LimitedRandomReader(size), size)
        client.put_object(bucket_name, object_name + "-2",
                          LimitedRandomReader(size), size)
        # List all object paths in bucket.
        objects = client.list_objects_v2(bucket_name, '', is_recursive)
        for obj in objects:
            _ = (obj.bucket_name, obj.object_name, obj.last_modified,
                 obj.etag, obj.size, obj.content_type)
    finally:
        client.remove_object(bucket_name, object_name + "-1")
        client.remove_object(bucket_name, object_name + "-2")
        client.remove_bucket(bucket_name)


# Helper method for test_list_incomplete_uploads
# and test_remove_incomplete_uploads tests
def create_upload_ids(bucket_name, object_name, n):
    # Create 'n' many incomplete upload ids and
    # return the list of created upload ids
    return [client._new_multipart_upload(
        bucket_name, object_name, {}) for _ in range(n)]


# Helper method for test_list_incomplete_uploads
# and test_remove_incomplete_uploads tests
def collect_incomplete_upload_ids(bucket_name, object_name):
    # Collect the upload ids from 'list_incomplete_uploads'
    # command, and return the list of created upload ids
    return [obj.upload_id for obj in client.list_incomplete_uploads(
        bucket_name, object_name, False)]


def test_remove_incomplete_upload(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_incomplete_upload(bucket_name, object_name)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        # Create 'no_of_upload_ids' many incomplete upload ids
        create_upload_ids(bucket_name, object_name, 3)
        # Remove all of the created upload ids
        client.remove_incomplete_upload(bucket_name, object_name)
        # Get the list of incomplete upload ids for object_name
        # using 'list_incomplete_uploads' command
        upload_ids_listed = collect_incomplete_upload_ids(bucket_name,
                                                          object_name)
        # Verify listed/returned upload id list
        if upload_ids_listed:
            # The list is not empty
            raise ValueError("There are still upload ids not removed")
    finally:
        client.remove_bucket(bucket_name)


def test_presigned_get_object_default_expiry(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "presigned_get_object(bucket_name, object_name, expires,
    #     response_headers)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        client.put_object(bucket_name, object_name, LimitedRandomReader(size),
                          size)
        presigned_get_object_url = client.presigned_get_object(
            bucket_name, object_name)
        response = http.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_presigned_get_object_expiry(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "presigned_get_object(bucket_name, object_name, expires,
    #     response_headers)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        client.put_object(bucket_name, object_name, LimitedRandomReader(size),
                          size)
        presigned_get_object_url = client.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=120))
        response = http.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()

        log_entry["args"]["presigned_get_object_url"] = (
            presigned_get_object_url)

        response = http.urlopen('GET', presigned_get_object_url)

        log_entry["args"]['response.status'] = response.status
        log_entry["args"]['response.reason'] = response.reason
        log_entry["args"]['response.headers'] = json.dumps(
            response.headers.__dict__)
        log_entry["args"]['response._body'] = response._body.decode('utf-8')

        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()

        presigned_get_object_url = client.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=1))

        # Wait for 2 seconds for the presigned url to expire
        time.sleep(2)
        response = http.urlopen('GET', presigned_get_object_url)

        log_entry["args"]['response.status-2'] = response.status
        log_entry["args"]['response.reason-2'] = response.reason
        log_entry["args"]['response.headers-2'] = json.dumps(
            response.headers.__dict__)
        log_entry["args"]['response._body-2'] = response._body.decode('utf-8')

        # Success with an expired url is considered to be a failure
        if response.status == 200:
            raise ValueError('Presigned get url failed to expire!')
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_presigned_get_object_response_headers(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "presigned_get_object(bucket_name, object_name, expires,
    #     response_headers)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())
    content_type = 'text/plain'
    content_language = 'en_US'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "content_type": content_type,
        "content_language": content_language,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        client.put_object(bucket_name, object_name, LimitedRandomReader(size),
                          size)
        presigned_get_object_url = client.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=120))

        response_headers = {
            'response-content-type': content_type,
            'response-content-language': content_language
        }
        presigned_get_object_url = client.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=120), response_headers)

        log_entry["args"]["presigned_get_object_url"] = (
            presigned_get_object_url)

        response = http.urlopen('GET', presigned_get_object_url)
        returned_content_type = response.headers['Content-Type']
        returned_content_language = response.headers['Content-Language']

        log_entry["args"]['response.status'] = response.status
        log_entry["args"]['response.reason'] = response.reason
        log_entry["args"]['response.headers'] = json.dumps(
            response.headers.__dict__)
        log_entry["args"]['response._body'] = response._body.decode('utf-8')
        log_entry["args"]['returned_content_type'] = returned_content_type
        log_entry["args"]['returned_content_language'] = (
            returned_content_language)

        if (response.status != 200 or
                returned_content_type != content_type or
                returned_content_language != content_language):
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_presigned_put_object_default_expiry(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "presigned_put_object(bucket_name, object_name, expires)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        presigned_put_object_url = client.presigned_put_object(
            bucket_name, object_name)
        response = http.urlopen('PUT',
                                presigned_put_object_url,
                                LimitedRandomReader(1 * KB))
        if response.status != 200:
            raise ResponseError(response,
                                'PUT',
                                bucket_name,
                                object_name).get_exception()
        client.stat_object(bucket_name, object_name)
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_presigned_put_object_expiry(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "presigned_put_object(bucket_name, object_name, expires)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    client.make_bucket(bucket_name)
    try:
        presigned_put_object_url = client.presigned_put_object(
            bucket_name, object_name, timedelta(seconds=1))
        # Wait for 2 seconds for the presigned url to expire
        time.sleep(2)
        response = http.urlopen('PUT',
                                presigned_put_object_url,
                                LimitedRandomReader(1 * KB))
        if response.status == 200:
            raise ValueError('Presigned put url failed to expire!')
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_presigned_post_policy(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "presigned_post_policy(post_policy)"

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()

    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    client.make_bucket(bucket_name)
    try:
        no_of_days = 10
        prefix = 'objectPrefix/'

        # Post policy.
        policy = PostPolicy()
        policy.set_bucket_name(bucket_name)
        policy.set_key_startswith(prefix)
        expires_date = datetime.utcnow() + timedelta(days=no_of_days)
        policy.set_expires(expires_date)
        # post_policy arg is a class. To avoid displaying meaningless value
        # for the class, policy settings are made part of the args for
        # clarity and debugging purposes.
        log_entry["args"]["post_policy"] = {'prefix': prefix,
                                            'expires_in_days': no_of_days}
        client.presigned_post_policy(policy)
    finally:
        client.remove_bucket(bucket_name)


def test_thread_safe(log_entry):
    # Create sha-sum value for the user provided
    # source file, 'test_file'
    test_file_sha_sum = _get_sha256sum(largefile)

    # Get a unique bucket_name and object_name
    bucket_name = generate_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    # A list of exceptions raised by get_object_and_check
    # called in multiple threads.
    exceptions = []

    # get_object_and_check() downloads an object, stores it in a file
    # and then calculates its checksum. In case of mismatch, a new
    # exception is generated and saved in exceptions.
    def get_object_and_check(index):
        try:
            local_file = "copied_file_{0}".format(index)
            client.fget_object(bucket_name, object_name, local_file)
            copied_file_sha_sum = _get_sha256sum(local_file)
            # Compare sha-sum values of the source file and the copied one
            if test_file_sha_sum != copied_file_sha_sum:
                raise ValueError(
                    'Sha-sum mismatch on multi-threaded put and '
                    'get objects')
        except Exception as e:
            exceptions.append(e)
        finally:
            # Remove downloaded file
            _ = os.path.isfile(local_file) and os.remove(local_file)

    client.make_bucket(bucket_name)
    no_of_threads = 5
    try:
        # Put/Upload 'no_of_threads' many objects
        # simultaneously using multi-threading
        for _ in range(no_of_threads):
            thread = Thread(target=client.fput_object,
                            args=(bucket_name, object_name, largefile))
            thread.start()
            thread.join()

        # Get/Download 'no_of_threads' many objects
        # simultaneously using multi-threading
        thread_list = []
        for i in range(no_of_threads):
            # Create dynamic/varying names for to be created threads
            thread_name = 'thread_{0}'.format(i)
            vars()[thread_name] = Thread(
                target=get_object_and_check, args=(i,))
            vars()[thread_name].start()
            thread_list.append(vars()[thread_name])

        # Wait until all threads to finish
        for t in thread_list:
            t.join()

        if exceptions:
            raise exceptions[0]
    finally:
        client.remove_object(bucket_name, object_name)
        client.remove_bucket(bucket_name)


def test_get_bucket_policy(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "get_bucket_policy(bucket_name)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }
    client.make_bucket(bucket_name)
    try:
        client.get_bucket_policy(bucket_name)
    except NoSuchBucketPolicy:
        pass
    finally:
        client.remove_bucket(bucket_name)


def get_policy_actions(stat):
    def listit(x):
        return x if isinstance(x, list) else [x]
    actions = [listit(s.get("Action")) for s in stat if s.get("Action")]
    actions = list(set(
        [item.replace("s3:", "") for sublist in actions for item in sublist]
    ))
    actions.sort()
    return actions


def policy_validated(bucket_name, policy):
    policy_dict = json.loads(
        client.get_bucket_policy(bucket_name).decode("utf-8"))
    actions = get_policy_actions(policy_dict.get('Statement'))
    expected_actions = get_policy_actions(policy.get('Statement'))
    return expected_actions == actions


def test_get_bucket_notification(log_entry):
    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    client.make_bucket(bucket_name)
    try:
        notification = client.get_bucket_notification(bucket_name)
        if notification:
            raise ValueError("Failed to receive an empty bucket notification")
    finally:
        client.remove_bucket(bucket_name)


def test_set_bucket_policy_readonly(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "set_bucket_policy(bucket_name, policy)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    client.make_bucket(bucket_name)
    try:
        # read-only policy
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetBucketLocation",
                    "Resource": "arn:aws:s3:::" + bucket_name
                },
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::" + bucket_name
                },
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::{0}/*".format(bucket_name)
                }
            ]
        }
        # Set read-only policy
        client.set_bucket_policy(bucket_name, json.dumps(policy))
        # Validate if the policy is set correctly
        if not policy_validated(bucket_name, policy):
            raise ValueError('Failed to set ReadOnly bucket policy')
    finally:
        client.remove_bucket(bucket_name)


def test_set_bucket_policy_readwrite(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function =
    #     "set_bucket_policy(bucket_name, prefix, policy_access)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    client.make_bucket(bucket_name)
    try:
        # Read-write policy
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["s3:GetBucketLocation"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::" + bucket_name],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                },
                {
                    "Action": ["s3:ListBucket"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::" + bucket_name],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                },
                {
                    "Action": ["s3:ListBucketMultipartUploads"],
                    "Sid": "",
                    "Resource": ["arn:aws:s3:::" + bucket_name],
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
                    "Resource": ["arn:aws:s3:::{0}/*".format(bucket_name)],
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"}
                }
            ]
        }
        # Set read-write policy
        client.set_bucket_policy(bucket_name, json.dumps(policy))
        # Validate if the policy is set correctly
        if not policy_validated(bucket_name, policy):
            raise ValueError('Failed to set ReadOnly bucket policy')
    finally:
        client.remove_bucket(bucket_name)


def test_remove_objects(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_objects(bucket_name, objects_iter)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    client.make_bucket(bucket_name)
    try:
        size = 1 * KB
        object_names = []
        # Upload some new objects to prepare for multi-object delete test.
        for i in range(10):
            object_name = "prefix-{0}".format(i)
            client.put_object(bucket_name, object_name,
                              LimitedRandomReader(size), size)
            object_names.append(object_name)
        log_entry["args"]["objects_iter"] = object_names

        # delete the objects in a single library call.
        for err in client.remove_objects(bucket_name, object_names):
            raise ValueError("Remove objects err: {}".format(err))
    finally:
        # Try to clean everything to keep our server intact
        for err in client.remove_objects(bucket_name, object_names):
            raise ValueError("Remove objects err: {}".format(err))
        client.remove_bucket(bucket_name)


def test_remove_bucket(log_entry):
    # default value for log_output.function attribute is;
    # log_output.function = "remove_bucket(bucket_name)"

    # Get a unique bucket_name
    bucket_name = generate_bucket_name()
    if is_s3():
        bucket_name += ".unique"

    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    if is_s3():
        log_entry["args"]["location"] = location = "us-east-1"
        client.make_bucket(bucket_name, location)
    else:
        client.make_bucket(bucket_name)

    # Removing bucket. This operation will only work if your bucket is empty.
    client.remove_bucket(bucket_name)


def main():
    """
    Functional testing of minio python library.
    """
    global client, testfile, largefile

    access_key = os.getenv('ACCESS_KEY')
    secret_key = os.getenv('SECRET_KEY')
    server_endpoint = os.getenv('SERVER_ENDPOINT', 'play.min.io')
    secure = os.getenv('ENABLE_HTTPS', '1') == '1'

    if server_endpoint == 'play.min.io':
        access_key = 'Q3AM3UQ867SPQQA43P2F'
        secret_key = 'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG'
        secure = True

    client = Minio(server_endpoint, access_key, secret_key, secure=secure)

    # Check if we are running in the mint environment.
    data_dir = os.getenv('DATA_DIR', '/mint/data')

    is_mint_env = (
        os.path.exists(data_dir) and
        os.path.exists(os.path.join(data_dir, 'datafile-1-MB')) and
        os.path.exists(os.path.join(data_dir, 'datafile-11-MB'))
    )

    # Enable trace
    # client.trace_on(sys.stderr)

    testfile = 'datafile-1-MB'
    largefile = 'datafile-11-MB'
    if is_mint_env:
        # Choose data files
        testfile = os.path.join(data_dir, 'datafile-1-MB')
        largefile = os.path.join(data_dir, 'datafile-11-MB')
    else:
        with open(testfile, 'wb') as file_data:
            shutil.copyfileobj(LimitedRandomReader(1 * MB), file_data)
        with open(largefile, 'wb') as file_data:
            shutil.copyfileobj(LimitedRandomReader(11 * MB), file_data)

    ssec_copy = ssec = None
    if secure:
        # Create a Customer Key of 32 Bytes for Server Side Encryption (SSE-C)
        cust_key = b'AABBCCDDAABBCCDDAABBCCDDAABBCCDD'
        # Create an SSE-C object with provided customer key
        ssec = SSE_C(cust_key)
        # Test copy_object for SSE-C
        ssec_copy = copy_SSE_C(cust_key)

    if isFullMode():
        tests = {
            test_make_bucket_default_region: None,
            test_make_bucket_with_region: None,
            test_negative_make_bucket_invalid_name: None,
            test_list_buckets: None,
            test_fput_object_small_file: {"sse": ssec} if ssec else None,
            test_fput_object_large_file: {"sse": ssec} if ssec else None,
            test_fput_object_with_content_type: None,
            test_copy_object_no_copy_condition: {
                "ssec_copy": ssec_copy, "ssec": ssec} if ssec else None,
            test_copy_object_etag_match: None,
            test_copy_object_with_metadata: None,
            test_copy_object_negative_etag_match: None,
            test_copy_object_modified_since: None,
            test_copy_object_unmodified_since: None,
            test_put_object: {"sse": ssec} if ssec else None,
            test_negative_put_object_with_path_segment: None,
            test_stat_object: {"sse": ssec} if ssec else None,
            test_get_object: {"sse": ssec} if ssec else None,
            test_fget_object: {"sse": ssec} if ssec else None,
            test_get_partial_object_with_default_length: None,
            test_get_partial_object: {"sse": ssec} if ssec else None,
            test_list_objects: None,
            test_list_objects_with_prefix: None,
            test_list_objects_with_1001_files: None,
            test_remove_incomplete_upload: None,
            test_list_objects_v2: None,
            test_presigned_get_object_default_expiry: None,
            test_presigned_get_object_expiry: None,
            test_presigned_get_object_response_headers: None,
            test_presigned_put_object_default_expiry: None,
            test_presigned_put_object_expiry: None,
            test_presigned_post_policy: None,
            test_thread_safe: None,
            test_get_bucket_policy: None,
            test_set_bucket_policy_readonly: None,
            test_set_bucket_policy_readwrite: None,
            test_get_bucket_notification: None,
            test_select_object_content: None,
        }
    else:
        tests = {
            test_make_bucket_default_region: None,
            test_list_buckets: None,
            test_put_object: {"sse": ssec} if ssec else None,
            test_stat_object: {"sse": ssec} if ssec else None,
            test_get_object: {"sse": ssec} if ssec else None,
            test_list_objects: None,
            test_remove_incomplete_upload: None,
            test_presigned_get_object_default_expiry: None,
            test_presigned_put_object_default_expiry: None,
            test_presigned_post_policy: None,
            test_copy_object_no_copy_condition: {
                "ssec_copy": ssec_copy, "ssec": ssec} if ssec else None,
            test_select_object_content: None,
            test_get_bucket_policy: None,
            test_set_bucket_policy_readonly: None,
            test_get_bucket_notification: None,
        }

    tests.update(
        {
            test_remove_object: None,
            test_remove_objects: None,
            test_remove_bucket: None,
        },
    )

    for test_name, arg_list in tests.items():
        args = ()
        kwargs = {}
        testit(test_name, *args, **kwargs)

        if arg_list:
            args = ()
            kwargs = arg_list
            testit(test_name, *args, **kwargs)

    # Remove temporary files.
    if not is_mint_env:
        os.remove(testfile)
        os.remove(largefile)


if __name__ == "__main__":
    try:
        main()
    except TestFailedException:
        sys.exit(1)
    except Exception as ex:
        print(ex)
        sys.exit(-1)
