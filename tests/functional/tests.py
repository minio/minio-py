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

# pylint: disable=too-many-lines
"""Functional tests of minio-py."""

from __future__ import absolute_import, division

import hashlib
import io
import json
import math
import os
import random
import shutil
import sys
import tempfile
import time
import traceback
from datetime import datetime, timedelta
from threading import Thread
from uuid import uuid4

import certifi
import urllib3

from minio import CopyConditions, Minio, PostPolicy
from minio.error import (APINotImplemented, InvalidBucketError,
                         NoSuchBucketPolicy, PreconditionFailed, ResponseError)
from minio.fold_case_dict import FoldCaseDict
from minio.select.helpers import calculate_crc
from minio.select.options import (CSVInput, CSVOutput, InputSerialization,
                                  OutputSerialization, RequestProgress,
                                  SelectObjectOptions)
from minio.sse import SseCustomerKey

if sys.version_info[0] == 2:
    from datetime import tzinfo  # pylint: disable=ungrouped-imports

    class UTC(tzinfo):
        """UTC"""

        def utcoffset(self, dt):
            return timedelta(0)

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return timedelta(0)

    UTC = UTC()
    from inspect import getargspec
    GETARGSSPEC = getargspec
else:
    from datetime import timezone  # pylint: disable=ungrouped-imports
    UTC = timezone.utc
    from inspect import getfullargspec  # pylint: disable=ungrouped-imports
    GETARGSSPEC = getfullargspec

_CLIENT = None  # initialized in main().
_TEST_FILE = None  # initialized in main().
_LARGE_FILE = None  # initialized in main().
_IS_AWS = None  # initialized in main().
KB = 1024
MB = 1024 * KB
HTTP = urllib3.PoolManager(
    cert_reqs='CERT_REQUIRED',
    ca_certs=os.environ.get('SSL_CERT_FILE') or certifi.where()
)


def _gen_bucket_name():
    """Generate random bucket name."""
    return "minio-py-test-{0}".format(uuid4())


def _get_sha256sum(filename):
    """Get SHA-256 checksum of given file."""
    with open(filename, 'rb') as file:
        contents = file.read()
        return hashlib.sha256(contents).hexdigest()


def _get_random_string(size):
    """Get random string of given size."""
    if not size:
        return ""

    chars = "abcdefghijklmnopqrstuvwxyz"
    chars *= int(math.ceil(size / len(chars)))
    chars = list(chars[:size])
    random.shuffle(chars)
    return "".join(chars)


class LimitedRandomReader:  # pylint: disable=too-few-public-methods
    """Random data reader of specified size."""

    def __init__(self, limit):
        self._limit = limit

    def read(self, size=64*KB):
        """Read random data of specified size."""
        if size < 0 or size > self._limit:
            size = self._limit

        data = _get_random_string(size)
        self._limit -= size
        return data.encode()


def _call(log_entry, func, *args, **kwargs):
    """Execute given function."""
    log_entry["method"] = func
    return func(*args, **kwargs)


class TestFailed(Exception):
    """Indicate test failed error."""


def _call_test(func, *args, **kwargs):
    """Execute given test function."""

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
    except Exception as exc:  # pylint: disable=broad-except
        log_entry["message"] = "{0}".format(exc)
        log_entry["error"] = traceback.format_exc()
        log_entry["status"] = "FAIL"

    if log_entry.get("method"):
        log_entry["function"] = "{0}({1})".format(
            log_entry["method"].__name__,
            # pylint: disable=deprecated-method
            ', '.join(GETARGSSPEC(log_entry["method"]).args[1:]))
    log_entry["args"] = {
        k: v for k, v in log_entry.get("args", {}).items() if v
    }
    log_entry["duration"] = int(
        round((time.time() - start_time) * 1000))
    log_entry["name"] = 'minio-py:' + log_entry["name"]
    log_entry["method"] = None
    print(json.dumps({k: v for k, v in log_entry.items() if v}))
    if log_entry["status"] == "FAIL":
        raise TestFailed()


def test_make_bucket_default_region(log_entry):
    """Test make_bucket() with default region."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "location": "default value ('us-east-1')",  # Default location
    }

    # Create a bucket with default bucket location
    _call(log_entry, _CLIENT.make_bucket, bucket_name)
    # Check if bucket was created properly
    _call(log_entry, _CLIENT.bucket_exists, bucket_name)
    # Remove bucket
    _call(log_entry, _CLIENT.remove_bucket, bucket_name)
    # Test passes
    log_entry["method"] = _CLIENT.make_bucket


def test_make_bucket_with_region(log_entry):
    """Test make_bucket() with region."""

    # Only test make bucket with region against AWS S3
    if not _IS_AWS:
        return

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    # A non-default location
    location = 'us-west-1'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "location": location,
    }

    # Create a bucket with default bucket location
    _call(log_entry, _CLIENT.make_bucket, bucket_name, location)
    # Check if bucket was created properly
    _call(log_entry, _CLIENT.bucket_exists, bucket_name)
    # Remove bucket
    _call(log_entry, _CLIENT.remove_bucket, bucket_name)
    # Test passes
    log_entry["method"] = _CLIENT.make_bucket


def test_negative_make_bucket_invalid_name(  # pylint: disable=invalid-name
        log_entry):
    """Test make_bucket() with invalid bucket name."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
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
            _call(log_entry, _CLIENT.make_bucket, bucket_name)
            # Check if bucket was created properly
            _call(log_entry, _CLIENT.bucket_exists, bucket_name)
            # Remove bucket
            _call(log_entry, _CLIENT.remove_bucket, bucket_name)
        except InvalidBucketError:
            pass
    # Test passes
    log_entry["method"] = _CLIENT.make_bucket
    log_entry["args"]['bucket_name'] = invalid_bucket_name_list


def test_list_buckets(log_entry):
    """Test list_buckets()."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()

    # Create a bucket with default bucket location
    _call(log_entry, _CLIENT.make_bucket, bucket_name)

    try:
        buckets = _CLIENT.list_buckets()
        for bucket in buckets:
            # bucket object should be of a valid value.
            if bucket.name and bucket.creation_date:
                continue
            raise ValueError('list_bucket api failure')
    finally:
        # Remove bucket
        _call(log_entry, _CLIENT.remove_bucket, bucket_name)


def test_select_object_content(log_entry):
    """Test select_object_content()."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    csvfile = 'test.csv'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": csvfile,
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        content = io.BytesIO(b"col1,col2,col3\none,two,three\nX,Y,Z\n")
        _CLIENT.put_object(bucket_name, csvfile, content,
                           len(content.getvalue()))

        options = SelectObjectOptions(
            expression="select * from s3object",
            input_serialization=InputSerialization(
                compression_type="NONE",
                csv=CSVInput(file_header_info="NONE",
                             record_delimiter="\n",
                             field_delimiter=",",
                             quote_character='"',
                             quote_escape_character='"',
                             comments="#",
                             allow_quoted_record_delimiter=False),
            ),
            output_serialization=OutputSerialization(
                csv=CSVOutput(quote_fields="ASNEEDED",
                              record_delimiter="\n",
                              field_delimiter=",",
                              quote_character='"',
                              quote_escape_character='"')
            ),
            request_progress=RequestProgress(enabled=False)
        )

        data = _CLIENT.select_object_content(bucket_name, csvfile, options)
        # Get the records
        records = io.BytesIO()
        for data_bytes in data.stream(10*KB):
            records.write(data_bytes.encode('utf-8'))

        expected_crc = calculate_crc(content.getvalue())
        generated_crc = calculate_crc(records.getvalue())
        if expected_crc != generated_crc:
            raise ValueError(
                'Data mismatch Expected : '
                '"col1,col2,col3\none,two,three\nX,Y,Z\n"',
                'Received {}', records)
    finally:
        _CLIENT.remove_object(bucket_name, csvfile)
        _CLIENT.remove_bucket(bucket_name)


def _test_fput_object(bucket_name, object_name, filename, metadata, sse):
    """Test fput_object()."""
    try:
        _CLIENT.make_bucket(bucket_name)
        if _IS_AWS:
            _CLIENT.fput_object(bucket_name, object_name, filename,
                                metadata=metadata, sse=sse)
        else:
            _CLIENT.fput_object(bucket_name, object_name, filename, sse=sse)

        _CLIENT.stat_object(bucket_name, object_name, sse=sse)
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_fput_object_small_file(log_entry, sse=None):
    """Test fput_object() with small file."""

    if sse:
        log_entry["name"] += "_with_SSE-C"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}-f".format(uuid4())
    metadata = {'x-amz-storage-class': 'STANDARD_IA'}

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": _TEST_FILE,
        "metadata": metadata,
    }

    _test_fput_object(bucket_name, object_name, _TEST_FILE, metadata, sse)


def test_fput_object_large_file(log_entry, sse=None):
    """Test fput_object() with large file."""

    if sse:
        log_entry["name"] += "_with_SSE-C"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}-large".format(uuid4())
    metadata = {'x-amz-storage-class': 'STANDARD_IA'}

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": _LARGE_FILE,
        "metadata": metadata,
    }

    # upload local large file through multipart.
    _test_fput_object(bucket_name, object_name, _LARGE_FILE, metadata, sse)


def test_fput_object_with_content_type(  # pylint: disable=invalid-name
        log_entry):
    """Test fput_object() with content-type."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}-f".format(uuid4())
    metadata = {'x-amz-storage-class': 'STANDARD_IA'}
    content_type = 'application/octet-stream'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": _TEST_FILE,
        "metadata": metadata,
        "content_type": content_type,
    }

    _test_fput_object(bucket_name, object_name, _TEST_FILE, metadata, None)


def _validate_stat(st_obj, expected_size, expected_meta, version_id=None):
    """Validate stat information."""

    received_modification_time = st_obj.last_modified
    received_etag = st_obj.etag
    received_metadata = FoldCaseDict(st_obj.metadata)
    received_content_type = st_obj.content_type
    received_size = st_obj.size
    received_is_dir = st_obj.is_dir

    if not isinstance(received_modification_time, time.struct_time):
        raise ValueError('Incorrect last_modified time type'
                         ', received type: ', type(received_modification_time))

    if not received_etag:
        raise ValueError('No Etag value is returned.')

    if st_obj.version_id != version_id:
        raise ValueError(
            "version-id mismatch. expected={0}, got={1}".format(
                version_id, st_obj.version_id,
            ),
        )

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


def test_copy_object_no_copy_condition(  # pylint: disable=invalid-name
        log_entry, ssec_copy=None, ssec=None):
    """Test copy_object() with no conditiions."""

    if ssec_copy or ssec:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        _CLIENT.put_object(bucket_name, object_source, reader, size, sse=ssec)
        _CLIENT.copy_object(bucket_name, object_copy,
                            '/' + bucket_name + '/' + object_source,
                            source_sse=ssec_copy, sse=ssec)
        st_obj = _CLIENT.stat_object(bucket_name, object_copy, sse=ssec)
        _validate_stat(st_obj, size, {})
    finally:
        _CLIENT.remove_object(bucket_name, object_source)
        _CLIENT.remove_object(bucket_name, object_copy)
        _CLIENT.remove_bucket(bucket_name)


def test_copy_object_with_metadata(log_entry):
    """Test copy_object() with metadata."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
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
        _CLIENT.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        _CLIENT.put_object(bucket_name, object_source, reader, size)
        # Perform a server side copy of an object
        _CLIENT.copy_object(bucket_name, object_copy,
                            '/' + bucket_name + '/' + object_source,
                            metadata=metadata)
        # Verification
        st_obj = _CLIENT.stat_object(bucket_name, object_copy)
        expected_metadata = {'x-amz-meta-testing-int': '1',
                             'x-amz-meta-testing-string': 'string'}
        _validate_stat(st_obj, size, expected_metadata)
    finally:
        _CLIENT.remove_object(bucket_name, object_source)
        _CLIENT.remove_object(bucket_name, object_copy)
        _CLIENT.remove_bucket(bucket_name)


def test_copy_object_etag_match(log_entry):
    """Test copy_object() with etag match condition."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        _CLIENT.put_object(bucket_name, object_source, reader, size)
        # Perform a server side copy of an object
        _CLIENT.copy_object(bucket_name, object_copy,
                            '/' + bucket_name + '/' + object_source)
        # Verification
        source_etag = _CLIENT.stat_object(bucket_name, object_source).etag
        copy_conditions = CopyConditions()
        copy_conditions.set_match_etag(source_etag)
        log_entry["args"]["conditions"] = {'set_match_etag': source_etag}
        _CLIENT.copy_object(bucket_name, object_copy,
                            '/' + bucket_name + '/' + object_source,
                            copy_conditions)
    finally:
        _CLIENT.remove_object(bucket_name, object_source)
        _CLIENT.remove_object(bucket_name, object_copy)
        _CLIENT.remove_bucket(bucket_name)


def test_copy_object_negative_etag_match(  # pylint: disable=invalid-name
        log_entry):
    """Test copy_object() with etag not match condition."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        _CLIENT.put_object(bucket_name, object_source, reader, size)
        try:
            # Perform a server side copy of an object
            # with incorrect pre-conditions and fail
            etag = 'test-etag'
            copy_conditions = CopyConditions()
            copy_conditions.set_match_etag(etag)
            log_entry["args"]["conditions"] = {'set_match_etag': etag}
            _CLIENT.copy_object(bucket_name, object_copy,
                                '/' + bucket_name + '/' + object_source,
                                copy_conditions)
        except PreconditionFailed as exc:
            if exc.message != (
                    "At least one of the preconditions you specified "
                    "did not hold."):
                raise
    finally:
        _CLIENT.remove_object(bucket_name, object_source)
        _CLIENT.remove_object(bucket_name, object_copy)
        _CLIENT.remove_bucket(bucket_name)


def test_copy_object_modified_since(log_entry):
    """Test copy_object() with modified since condition."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        _CLIENT.put_object(bucket_name, object_source, reader, size)
        # Set up the 'modified_since' copy condition
        copy_conditions = CopyConditions()
        mod_since = datetime(2014, 4, 1, tzinfo=UTC)
        copy_conditions.set_modified_since(mod_since)
        log_entry["args"]["conditions"] = {
            'set_modified_since': mod_since.strftime('%c')}
        # Perform a server side copy of an object
        # and expect the copy to complete successfully
        _CLIENT.copy_object(bucket_name, object_copy,
                            '/' + bucket_name + '/' + object_source,
                            copy_conditions)
    finally:
        _CLIENT.remove_object(bucket_name, object_source)
        _CLIENT.remove_object(bucket_name, object_copy)
        _CLIENT.remove_bucket(bucket_name)


def test_copy_object_unmodified_since(  # pylint: disable=invalid-name
        log_entry):
    """Test copy_object() with unmodified since condition."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    object_source = object_name + "-source"
    object_copy = object_name + "-copy"

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_source": object_source,
        "object_name": object_copy,
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        # Upload a streaming object of 1 KiB
        size = 1 * KB
        reader = LimitedRandomReader(size)
        _CLIENT.put_object(bucket_name, object_source, reader, size)
        # Set up the 'unmodified_since' copy condition
        copy_conditions = CopyConditions()
        unmod_since = datetime(2014, 4, 1, tzinfo=UTC)
        copy_conditions.set_unmodified_since(unmod_since)
        log_entry["args"]["conditions"] = {
            'set_unmodified_since': unmod_since.strftime('%c')}
        try:
            # Perform a server side copy of an object and expect
            # the copy to fail since the creation/modification
            # time is now, way later than unmodification time, April 1st, 2014
            _CLIENT.copy_object(bucket_name, object_copy,
                                '/' + bucket_name + '/' + object_source,
                                copy_conditions)
        except PreconditionFailed as exc:
            if exc.message != (
                    "At least one of the preconditions you specified "
                    "did not hold."):
                raise
    finally:
        _CLIENT.remove_object(bucket_name, object_source)
        _CLIENT.remove_object(bucket_name, object_copy)
        _CLIENT.remove_bucket(bucket_name)


def test_put_object(log_entry, sse=None):
    """Test put_object()."""

    if sse:
        log_entry["name"] += "_SSE"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "length": length,
        "data": "LimitedRandomReader(1 * MB)"
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        # Put/Upload a streaming object of 1 MiB
        reader = LimitedRandomReader(length)
        _CLIENT.put_object(bucket_name, object_name, reader, length, sse=sse)
        _CLIENT.stat_object(bucket_name, object_name, sse=sse)

        # Put/Upload a streaming object of 11 MiB
        log_entry["args"]["length"] = length = 11 * MB
        reader = LimitedRandomReader(length)
        log_entry["args"]["data"] = "LimitedRandomReader(11 * MB)"
        log_entry["args"]["metadata"] = metadata = {
            'x-amz-meta-testing': 'value', 'test-key': 'value2'}
        log_entry["args"]["content_type"] = content_type = (
            "application/octet-stream")
        log_entry["args"]["object_name"] = object_name + "-metadata"
        _CLIENT.put_object(bucket_name, object_name + "-metadata", reader,
                           length, content_type, metadata, sse=sse)
        # Stat on the uploaded object to check if it exists
        # Fetch saved stat metadata on a previously uploaded object with
        # metadata.
        st_obj = _CLIENT.stat_object(bucket_name, object_name + "-metadata",
                                     sse=sse)
        normalized_meta = FoldCaseDict(st_obj.metadata)
        if 'x-amz-meta-testing' not in normalized_meta:
            raise ValueError("Metadata key 'x-amz-meta-testing' not found")
        value = normalized_meta['x-amz-meta-testing']
        if value != 'value':
            raise ValueError('Metadata key has unexpected'
                             ' value {0}'.format(value))
        if 'x-amz-meta-test-key' not in normalized_meta:
            raise ValueError("Metadata key 'x-amz-meta-test-key' not found")
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_object(bucket_name, object_name+'-metadata')
        _CLIENT.remove_bucket(bucket_name)


def test_negative_put_object_with_path_segment(  # pylint: disable=invalid-name
        log_entry):
    """Test put_object() failure with path segment."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "/a/b/c/{0}".format(uuid4())
    length = 0

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "length": length,
        "data": "",
    }

    try:
        _CLIENT.make_bucket(bucket_name)
        _CLIENT.put_object(bucket_name, object_name, io.BytesIO(b''), 0)
        _CLIENT.remove_object(bucket_name, object_name)
    except ResponseError as err:
        if err.code != 'XMinioInvalidObjectName':
            raise
    finally:
        _CLIENT.remove_bucket(bucket_name)


def _test_stat_object(log_entry, sse=None, version_check=False):
    """Test stat_object()."""

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "length": length,
        "data": "LimitedRandomReader(1 * MB)"
    }

    version_id1 = None
    version_id2 = None

    _CLIENT.make_bucket(bucket_name)
    try:
        if version_check:
            _CLIENT.enable_bucket_versioning(bucket_name)
        # Put/Upload a streaming object of 1 MiB
        reader = LimitedRandomReader(length)
        _, version_id1 = _CLIENT.put_object(
            bucket_name, object_name, reader, length, sse=sse,
        )
        _CLIENT.stat_object(
            bucket_name, object_name, sse=sse, version_id=version_id1,
        )

        # Put/Upload a streaming object of 11 MiB
        log_entry["args"]["length"] = length = 11 * MB
        reader = LimitedRandomReader(length)
        log_entry["args"]["data"] = "LimitedRandomReader(11 * MB)"
        log_entry["args"]["metadata"] = metadata = {
            'X-Amz-Meta-Testing': 'value'}
        log_entry["args"]["content_type"] = content_type = (
            "application/octet-stream")
        log_entry["args"]["object_name"] = object_name + "-metadata"
        _, version_id2 = _CLIENT.put_object(
            bucket_name, object_name + "-metadata", reader,
            length, content_type, metadata, sse=sse,
        )
        # Stat on the uploaded object to check if it exists
        # Fetch saved stat metadata on a previously uploaded object with
        # metadata.
        st_obj = _CLIENT.stat_object(
            bucket_name, object_name + "-metadata",
            sse=sse, version_id=version_id2,
        )
        # Verify the collected stat data.
        _validate_stat(
            st_obj, length, FoldCaseDict(metadata), version_id=version_id2,
        )
    finally:
        _CLIENT.remove_object(bucket_name, object_name, version_id=version_id1)
        _CLIENT.remove_object(
            bucket_name, object_name+'-metadata', version_id=version_id2,
        )
        _CLIENT.remove_bucket(bucket_name)


def test_stat_object(log_entry, sse=None):
    """Test stat_object()."""
    _test_stat_object(log_entry, sse)


def test_stat_object_version(log_entry, sse=None):
    """Test stat_object() of versioned object."""
    _test_stat_object(log_entry, sse, version_check=True)


def _test_remove_object(log_entry, version_check=False):
    """Test remove_object()."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * KB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        if version_check:
            _CLIENT.enable_bucket_versioning(bucket_name)
        _, version_id = _CLIENT.put_object(
            bucket_name, object_name, LimitedRandomReader(length), length,
        )
        _CLIENT.remove_object(bucket_name, object_name, version_id=version_id)
    finally:
        _CLIENT.remove_bucket(bucket_name)


def test_remove_object(log_entry):
    """Test remove_object()."""
    _test_remove_object(log_entry)


def test_remove_object_version(log_entry):
    """Test remove_object() of versioned object."""
    _test_remove_object(log_entry, version_check=True)


def _test_get_object(log_entry, sse=None, version_check=False):
    """Test get_object()."""

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    version_id = None
    try:
        if version_check:
            _CLIENT.enable_bucket_versioning(bucket_name)
        _, version_id = _CLIENT.put_object(
            bucket_name, object_name, LimitedRandomReader(length),
            length, sse=sse,
        )
        # Get/Download a full object, iterate on response to save to disk
        object_data = _CLIENT.get_object(
            bucket_name, object_name, sse=sse, version_id=version_id,
        )
        newfile = 'newfile جديد'
        with open(newfile, 'wb') as file_data:
            shutil.copyfileobj(object_data, file_data)
        os.remove(newfile)
    finally:
        _CLIENT.remove_object(bucket_name, object_name, version_id=version_id)
        _CLIENT.remove_bucket(bucket_name)


def test_get_object(log_entry, sse=None):
    """Test get_object()."""
    _test_get_object(log_entry, sse)


def test_get_object_version(log_entry, sse=None):
    """Test get_object() for versioned object."""
    _test_get_object(log_entry, sse, version_check=True)


def _test_fget_object(log_entry, sse=None, version_check=False):
    """Test fget_object()."""

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    tmpfd, tmpfile = tempfile.mkstemp()
    os.close(tmpfd)
    length = 1 * MB

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "file_path": tmpfile
    }

    _CLIENT.make_bucket(bucket_name)
    version_id = None
    try:
        if version_check:
            _CLIENT.enable_bucket_versioning(bucket_name)
        _, version_id = _CLIENT.put_object(
            bucket_name, object_name, LimitedRandomReader(length),
            length, sse=sse,
        )
        # Get/Download a full object and save locally at path
        _CLIENT.fget_object(
            bucket_name, object_name, tmpfile, sse=sse, version_id=version_id,
        )
        os.remove(tmpfile)
    finally:
        _CLIENT.remove_object(bucket_name, object_name, version_id=version_id)
        _CLIENT.remove_bucket(bucket_name)


def test_fget_object(log_entry, sse=None):
    """Test fget_object()."""
    _test_fget_object(log_entry, sse)


def test_fget_object_version(log_entry, sse=None):
    """Test fget_object() of versioned object."""
    _test_fget_object(log_entry, sse, version_check=True)


def test_get_partial_object_with_default_length(  # pylint: disable=invalid-name
        log_entry, sse=None):
    """Test get_partial_object() with default length."""

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    size = 1 * MB
    length = 1000
    offset = size - length

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "offset": offset
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        _CLIENT.put_object(bucket_name, object_name,
                           LimitedRandomReader(size), size, sse=sse)
        # Get half of the object
        object_data = _CLIENT.get_partial_object(bucket_name, object_name,
                                                 offset, sse=sse)
        newfile = 'newfile'
        with open(newfile, 'wb') as file_data:
            for data in object_data:
                file_data.write(data)
        # Check if the new file is the right size
        new_file_size = os.path.getsize(newfile)
        os.remove(newfile)
        if new_file_size != length:
            raise ValueError('Unexpected file size after running ')
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_get_partial_object(log_entry, sse=None):
    """Test get_partial_object()."""

    if sse:
        log_entry["name"] += "_SSEC"

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    size = 1 * MB
    offset = int(size / 2)
    length = offset - 1000

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "offset": offset
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        _CLIENT.put_object(bucket_name, object_name,
                           LimitedRandomReader(size), size, sse=sse)
        # Get half of the object
        object_data = _CLIENT.get_partial_object(bucket_name, object_name,
                                                 offset, length, sse=sse)
        newfile = 'newfile'
        with open(newfile, 'wb') as file_data:
            for data in object_data:
                file_data.write(data)
        # Check if the new file is the right size
        new_file_size = os.path.getsize(newfile)
        os.remove(newfile)
        if new_file_size != length:
            raise ValueError('Unexpected file size after running ')
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def _test_list_objects(log_entry, version2=False, version_check=False):
    """Test list_objects()."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    is_recursive = True

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "recursive": is_recursive,
    }

    _CLIENT.make_bucket(bucket_name)
    version_id1 = None
    version_id2 = None
    try:
        if version_check:
            _CLIENT.enable_bucket_versioning(bucket_name)
        size = 1 * KB
        _, version_id1 = _CLIENT.put_object(
            bucket_name, object_name + "-1", LimitedRandomReader(size), size,
        )
        _, version_id2 = _CLIENT.put_object(
            bucket_name, object_name + "-2", LimitedRandomReader(size), size,
        )
        # List all object paths in bucket.
        if version2:
            objects = _CLIENT.list_objects_v2(
                bucket_name, '', is_recursive, include_version=version_check,
            )
        else:
            objects = _CLIENT.list_objects(
                bucket_name, '', is_recursive, include_version=version_check,
            )
        for obj in objects:
            _ = (obj.bucket_name, obj.object_name, obj.last_modified,
                 obj.etag, obj.size, obj.content_type)
            if obj.version_id not in [version_id1, version_id2]:
                raise ValueError(
                    "version ID mismatch. expected=any{0}, got:{1}".format(
                        [version_id1, version_id2], obj.verion_id,
                    )
                )
    finally:
        _CLIENT.remove_object(
            bucket_name, object_name + "-1", version_id=version_id1,
        )
        _CLIENT.remove_object(
            bucket_name, object_name + "-2", version_id=version_id2,
        )
        _CLIENT.remove_bucket(bucket_name)


def test_list_objects(log_entry):
    """Test list_objects()."""
    _test_list_objects(log_entry)


def test_list_object_versions(log_entry):
    """Test list_objects()."""
    _test_list_objects(log_entry, version_check=True)


def _test_list_objects_api(bucket_name, expected_no, *argv):
    """Test list_objects()."""

    # argv is composed of prefix and recursive arguments of
    # list_objects api. They are both supposed to be passed as strings.
    objects = _CLIENT.list_objects(bucket_name, *argv)

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
    """Test list_objects() with prefix."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        size = 1 * KB
        no_of_created_files = 4
        path_prefix = ""
        # Create files and directories
        for i in range(no_of_created_files):
            _CLIENT.put_object(bucket_name,
                               "{0}{1}_{2}".format(
                                   path_prefix,
                                   i,
                                   object_name,
                               ),
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
        _test_list_objects_api(bucket_name, no_of_created_files, prefix, True)

        # List objects at the top level with no prefix and no recursive option
        # Expect only the top 2 objects to be listed
        _test_list_objects_api(bucket_name, 2)

        # List objects for '0' directory/prefix without recursive option
        # Expect 2 object (directory '0' and '0_' object) to be listed
        log_entry["args"]["prefix"] = prefix = "0"
        _test_list_objects_api(bucket_name, 2, prefix)

        # List objects for '0/' directory/prefix without recursive option
        # Expect only 2 objects under directory '0/' to be listed,
        # non-recursive
        log_entry["args"]["prefix"] = prefix = "0/"
        _test_list_objects_api(bucket_name, 2, prefix)

        # List objects for '0/' directory/prefix, recursively
        # Expect 2 objects to be listed
        log_entry["args"]["prefix"] = prefix = "0/"
        log_entry["args"]["recursive"] = recursive = "True"
        _test_list_objects_api(bucket_name, 3, prefix, recursive)

        # List object with '0/1/2/' directory/prefix, non-recursive
        # Expect the single object under directory '0/1/2/' to be listed
        log_entry["args"]["prefix"] = prefix = "0/1/2/"
        _test_list_objects_api(bucket_name, 1, prefix)
    finally:
        path_prefix = ""
        for i in range(no_of_created_files):
            _CLIENT.remove_object(
                bucket_name,
                "{0}{1}_{2}".format(path_prefix, i, object_name))
            path_prefix = "{0}{1}/".format(path_prefix, i)
        _CLIENT.remove_bucket(bucket_name)
    # Test passes
    log_entry["args"]["prefix"] = (
        "Several prefix/recursive combinations are tested")
    log_entry["args"]["recursive"] = (
        'Several prefix/recursive combinations are tested')


def test_list_objects_with_1001_files(  # pylint: disable=invalid-name
        log_entry):
    """Test list_objects() with more 1000 objects."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": "{0}_0 ~ {0}_1000".format(object_name),
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        size = 1 * KB
        no_of_created_files = 2000
        # Create files and directories
        for i in range(no_of_created_files):
            _CLIENT.put_object(bucket_name,
                               "{0}_{1}".format(object_name, i),
                               LimitedRandomReader(size), size)

        # List objects and check if 1001 files are returned
        _test_list_objects_api(bucket_name, no_of_created_files)
    finally:
        for i in range(no_of_created_files):
            _CLIENT.remove_object(bucket_name,
                                  "{0}_{1}".format(object_name, i))
        _CLIENT.remove_bucket(bucket_name)


def test_list_objects_v2(log_entry):
    """Test list_objects_v2()."""
    _test_list_objects(log_entry, version2=True)


def test_list_object_versions_v2(log_entry):
    """Test list_objects_v2() of versioned object."""
    _test_list_objects(log_entry, version2=True, version_check=True)


def _create_upload_ids(bucket_name, object_name, count):
    """Create new upload IDs for given bucket and object of given count."""
    return [_CLIENT._new_multipart_upload(  # pylint: disable=protected-access
        bucket_name, object_name, {}) for _ in range(count)]


def _get_incomplete_upload_ids(bucket_name, object_name):
    """Get all upload IDs of given bucket and object."""
    return [obj.upload_id for obj in _CLIENT.list_incomplete_uploads(
        bucket_name, object_name, False)]


def test_remove_incomplete_upload(log_entry):
    """Test remove_incomplete_upload()."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        # Create 'no_of_upload_ids' many incomplete upload ids
        _create_upload_ids(bucket_name, object_name, 3)
        # Remove all of the created upload ids
        _CLIENT.remove_incomplete_upload(bucket_name, object_name)
        # Get the list of incomplete upload ids for object_name
        # using 'list_incomplete_uploads' command
        upload_ids_listed = _get_incomplete_upload_ids(bucket_name,
                                                       object_name)
        # Verify listed/returned upload id list
        if upload_ids_listed:
            # The list is not empty
            raise ValueError("There are still upload ids not removed")
    finally:
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_get_object_default_expiry(  # pylint: disable=invalid-name
        log_entry):
    """Test presigned_get_object() with default expiry."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        size = 1 * KB
        _CLIENT.put_object(bucket_name, object_name, LimitedRandomReader(size),
                           size)
        presigned_get_object_url = _CLIENT.presigned_get_object(
            bucket_name, object_name)
        response = HTTP.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_get_object_expiry(  # pylint: disable=invalid-name
        log_entry):
    """Test presigned_get_object() with expiry."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        size = 1 * KB
        _CLIENT.put_object(bucket_name, object_name, LimitedRandomReader(size),
                           size)
        presigned_get_object_url = _CLIENT.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=120))
        response = HTTP.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()

        log_entry["args"]["presigned_get_object_url"] = (
            presigned_get_object_url)

        response = HTTP.urlopen('GET', presigned_get_object_url)

        log_entry["args"]['response.status'] = response.status
        log_entry["args"]['response.reason'] = response.reason
        log_entry["args"]['response.headers'] = json.dumps(
            response.headers.__dict__)
        # pylint: disable=protected-access
        log_entry["args"]['response._body'] = response._body.decode('utf-8')

        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()

        presigned_get_object_url = _CLIENT.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=1))

        # Wait for 2 seconds for the presigned url to expire
        time.sleep(2)
        response = HTTP.urlopen('GET', presigned_get_object_url)

        log_entry["args"]['response.status-2'] = response.status
        log_entry["args"]['response.reason-2'] = response.reason
        log_entry["args"]['response.headers-2'] = json.dumps(
            response.headers.__dict__)
        log_entry["args"]['response._body-2'] = response._body.decode('utf-8')

        # Success with an expired url is considered to be a failure
        if response.status == 200:
            raise ValueError('Presigned get url failed to expire!')
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_get_object_response_headers(  # pylint: disable=invalid-name
        log_entry):
    """Test presigned_get_object() with headers."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())
    content_type = 'text/plain'
    content_language = 'en_US'

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "content_type": content_type,
        "content_language": content_language,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        size = 1 * KB
        _CLIENT.put_object(bucket_name, object_name, LimitedRandomReader(size),
                           size)
        presigned_get_object_url = _CLIENT.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=120))

        response_headers = {
            'response-content-type': content_type,
            'response-content-language': content_language
        }
        presigned_get_object_url = _CLIENT.presigned_get_object(
            bucket_name, object_name, timedelta(seconds=120), response_headers)

        log_entry["args"]["presigned_get_object_url"] = (
            presigned_get_object_url)

        response = HTTP.urlopen('GET', presigned_get_object_url)
        returned_content_type = response.headers['Content-Type']
        returned_content_language = response.headers['Content-Language']

        log_entry["args"]['response.status'] = response.status
        log_entry["args"]['response.reason'] = response.reason
        log_entry["args"]['response.headers'] = json.dumps(
            response.headers.__dict__)
        # pylint: disable=protected-access
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
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_get_object_version(  # pylint: disable=invalid-name
        log_entry):
    """Test presigned_get_object() of versioned object."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    version_id = None
    try:
        _CLIENT.enable_bucket_versioning(bucket_name)
        size = 1 * KB
        _, version_id = _CLIENT.put_object(
            bucket_name, object_name, LimitedRandomReader(size), size,
        )
        presigned_get_object_url = _CLIENT.presigned_get_object(
            bucket_name, object_name, version_id=version_id,
        )
        response = HTTP.urlopen('GET', presigned_get_object_url)
        if response.status != 200:
            raise ResponseError(response,
                                'GET',
                                bucket_name,
                                object_name).get_exception()
    finally:
        _CLIENT.remove_object(bucket_name, object_name, version_id=version_id)
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_put_object_default_expiry(  # pylint: disable=invalid-name
        log_entry):
    """Test presigned_put_object() with default expiry."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        presigned_put_object_url = _CLIENT.presigned_put_object(
            bucket_name, object_name)
        response = HTTP.urlopen('PUT',
                                presigned_put_object_url,
                                LimitedRandomReader(1 * KB))
        if response.status != 200:
            raise ResponseError(response,
                                'PUT',
                                bucket_name,
                                object_name).get_exception()
        _CLIENT.stat_object(bucket_name, object_name)
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_put_object_expiry(  # pylint: disable=invalid-name
        log_entry):
    """Test presigned_put_object() with expiry."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
    object_name = "{0}".format(uuid4())

    log_entry["args"] = {
        "bucket_name": bucket_name,
        "object_name": object_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        presigned_put_object_url = _CLIENT.presigned_put_object(
            bucket_name, object_name, timedelta(seconds=1))
        # Wait for 2 seconds for the presigned url to expire
        time.sleep(2)
        response = HTTP.urlopen('PUT',
                                presigned_put_object_url,
                                LimitedRandomReader(1 * KB))
        if response.status == 200:
            raise ValueError('Presigned put url failed to expire!')
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_presigned_post_policy(log_entry):
    """Test presigned_post_policy()."""

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()

    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    _CLIENT.make_bucket(bucket_name)
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
        _CLIENT.presigned_post_policy(policy)
    finally:
        _CLIENT.remove_bucket(bucket_name)


def test_thread_safe(log_entry):
    """Test thread safety."""

    # Create sha-sum value for the user provided
    # source file, 'test_file'
    test_file_sha_sum = _get_sha256sum(_LARGE_FILE)

    # Get a unique bucket_name and object_name
    bucket_name = _gen_bucket_name()
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
            _CLIENT.fget_object(bucket_name, object_name, local_file)
            copied_file_sha_sum = _get_sha256sum(local_file)
            # Compare sha-sum values of the source file and the copied one
            if test_file_sha_sum != copied_file_sha_sum:
                raise ValueError(
                    'Sha-sum mismatch on multi-threaded put and '
                    'get objects')
        except Exception as exc:  # pylint: disable=broad-except
            exceptions.append(exc)
        finally:
            # Remove downloaded file
            _ = os.path.isfile(local_file) and os.remove(local_file)

    _CLIENT.make_bucket(bucket_name)
    no_of_threads = 5
    try:
        # Put/Upload 'no_of_threads' many objects
        # simultaneously using multi-threading
        for _ in range(no_of_threads):
            thread = Thread(target=_CLIENT.fput_object,
                            args=(bucket_name, object_name, _LARGE_FILE))
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
        for thread in thread_list:
            thread.join()

        if exceptions:
            raise exceptions[0]
    finally:
        _CLIENT.remove_object(bucket_name, object_name)
        _CLIENT.remove_bucket(bucket_name)


def test_get_bucket_policy(log_entry):
    """Test get_bucket_policy()."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }
    _CLIENT.make_bucket(bucket_name)
    try:
        _CLIENT.get_bucket_policy(bucket_name)
    except NoSuchBucketPolicy:
        pass
    finally:
        _CLIENT.remove_bucket(bucket_name)


def _get_policy_actions(stat):
    """Get policy actions from stat information."""

    def listit(value):
        return value if isinstance(value, list) else [value]
    actions = [listit(s.get("Action")) for s in stat if s.get("Action")]
    actions = list(set(
        item.replace("s3:", "") for sublist in actions for item in sublist
    ))
    actions.sort()
    return actions


def _validate_policy(bucket_name, policy):
    """Validate policy."""
    policy_dict = json.loads(
        _CLIENT.get_bucket_policy(bucket_name).decode("utf-8"))
    actions = _get_policy_actions(policy_dict.get('Statement'))
    expected_actions = _get_policy_actions(policy.get('Statement'))
    return expected_actions == actions


def test_get_bucket_notification(log_entry):
    """Test get_bucket_notification()."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    _CLIENT.make_bucket(bucket_name)
    try:
        notification = _CLIENT.get_bucket_notification(bucket_name)
        if notification:
            raise ValueError("Failed to receive an empty bucket notification")
    finally:
        _CLIENT.remove_bucket(bucket_name)


def test_set_bucket_policy_readonly(log_entry):
    """Test set_bucket_policy() with readonly policy."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    _CLIENT.make_bucket(bucket_name)
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
        _CLIENT.set_bucket_policy(bucket_name, json.dumps(policy))
        # Validate if the policy is set correctly
        if not _validate_policy(bucket_name, policy):
            raise ValueError('Failed to set ReadOnly bucket policy')
    finally:
        _CLIENT.remove_bucket(bucket_name)


def test_set_bucket_policy_readwrite(  # pylint: disable=invalid-name
        log_entry):
    """Test set_bucket_policy() with read/write policy."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    _CLIENT.make_bucket(bucket_name)
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
        _CLIENT.set_bucket_policy(bucket_name, json.dumps(policy))
        # Validate if the policy is set correctly
        if not _validate_policy(bucket_name, policy):
            raise ValueError('Failed to set ReadOnly bucket policy')
    finally:
        _CLIENT.remove_bucket(bucket_name)


def _test_remove_objects(log_entry, version_check=False):
    """Test remove_objects()."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    _CLIENT.make_bucket(bucket_name)
    object_names = []
    try:
        if version_check:
            _CLIENT.enable_bucket_versioning(bucket_name)
        size = 1 * KB
        # Upload some new objects to prepare for multi-object delete test.
        for i in range(10):
            object_name = "prefix-{0}".format(i)
            _, version_id = _CLIENT.put_object(
                bucket_name, object_name, LimitedRandomReader(size), size,
            )
            object_names.append(
                (object_name, version_id) if version_check else object_name,
            )
        log_entry["args"]["objects_iter"] = object_names

        # delete the objects in a single library call.
        for err in _CLIENT.remove_objects(bucket_name, object_names):
            raise ValueError("Remove objects err: {}".format(err))
    finally:
        # Try to clean everything to keep our server intact
        for err in _CLIENT.remove_objects(bucket_name, object_names):
            raise ValueError("Remove objects err: {}".format(err))
        _CLIENT.remove_bucket(bucket_name)


def test_remove_objects(log_entry):
    """Test remove_objects()."""
    _test_remove_objects(log_entry)


def test_remove_object_versions(log_entry):
    """Test remove_objects()."""
    _test_remove_objects(log_entry, version_check=True)


def test_remove_bucket(log_entry):
    """Test remove_bucket()."""

    # Get a unique bucket_name
    bucket_name = _gen_bucket_name()
    if _IS_AWS:
        bucket_name += ".unique"

    log_entry["args"] = {
        "bucket_name": bucket_name,
    }

    if _IS_AWS:
        log_entry["args"]["location"] = location = "us-east-1"
        _CLIENT.make_bucket(bucket_name, location)
    else:
        _CLIENT.make_bucket(bucket_name)

    # Removing bucket. This operation will only work if your bucket is empty.
    _CLIENT.remove_bucket(bucket_name)


def main():
    """
    Functional testing of minio python library.
    """
    # pylint: disable=global-statement
    global _CLIENT, _TEST_FILE, _LARGE_FILE, _IS_AWS

    access_key = os.getenv('ACCESS_KEY')
    secret_key = os.getenv('SECRET_KEY')
    server_endpoint = os.getenv('SERVER_ENDPOINT', 'play.min.io')
    secure = os.getenv('ENABLE_HTTPS', '1') == '1'

    if server_endpoint == 'play.min.io':
        access_key = 'Q3AM3UQ867SPQQA43P2F'
        secret_key = 'zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG'
        secure = True

    _CLIENT = Minio(server_endpoint, access_key, secret_key, secure=secure)
    _IS_AWS = ".amazonaws.com" in server_endpoint

    # Check if we are running in the mint environment.
    data_dir = os.getenv('DATA_DIR', '/mint/data')

    is_mint_env = (
        os.path.exists(data_dir) and
        os.path.exists(os.path.join(data_dir, 'datafile-1-MB')) and
        os.path.exists(os.path.join(data_dir, 'datafile-11-MB'))
    )

    # Enable trace
    # _CLIENT.trace_on(sys.stderr)

    _TEST_FILE = 'datafile-1-MB'
    _LARGE_FILE = 'datafile-11-MB'
    if is_mint_env:
        # Choose data files
        _TEST_FILE = os.path.join(data_dir, 'datafile-1-MB')
        _LARGE_FILE = os.path.join(data_dir, 'datafile-11-MB')
    else:
        with open(_TEST_FILE, 'wb') as file_data:
            shutil.copyfileobj(LimitedRandomReader(1 * MB), file_data)
        with open(_LARGE_FILE, 'wb') as file_data:
            shutil.copyfileobj(LimitedRandomReader(11 * MB), file_data)

    ssec = None
    if secure:
        # Create a Customer Key of 32 Bytes for Server Side Encryption (SSE-C)
        cust_key = b'AABBCCDDAABBCCDDAABBCCDDAABBCCDD'
        # Create an SSE-C object with provided customer key
        ssec = SseCustomerKey(cust_key)

    if os.getenv("MINT_MODE") == "full":
        tests = {
            test_make_bucket_default_region: None,
            test_make_bucket_with_region: None,
            test_negative_make_bucket_invalid_name: None,
            test_list_buckets: None,
            test_fput_object_small_file: {"sse": ssec} if ssec else None,
            test_fput_object_large_file: {"sse": ssec} if ssec else None,
            test_fput_object_with_content_type: None,
            test_copy_object_no_copy_condition: {
                "ssec_copy": ssec, "ssec": ssec} if ssec else None,
            test_copy_object_etag_match: None,
            test_copy_object_with_metadata: None,
            test_copy_object_negative_etag_match: None,
            test_copy_object_modified_since: None,
            test_copy_object_unmodified_since: None,
            test_put_object: {"sse": ssec} if ssec else None,
            test_negative_put_object_with_path_segment: None,
            test_stat_object: {"sse": ssec} if ssec else None,
            test_stat_object_version: {"sse": ssec} if ssec else None,
            test_get_object: {"sse": ssec} if ssec else None,
            test_get_object_version: {"sse": ssec} if ssec else None,
            test_fget_object: {"sse": ssec} if ssec else None,
            test_fget_object_version: {"sse": ssec} if ssec else None,
            test_get_partial_object_with_default_length: None,
            test_get_partial_object: {"sse": ssec} if ssec else None,
            test_list_objects: None,
            test_list_object_versions: None,
            test_list_objects_with_prefix: None,
            test_list_objects_with_1001_files: None,
            test_remove_incomplete_upload: None,
            test_list_objects_v2: None,
            test_list_object_versions_v2: None,
            test_presigned_get_object_default_expiry: None,
            test_presigned_get_object_expiry: None,
            test_presigned_get_object_response_headers: None,
            test_presigned_get_object_version: None,
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
            test_stat_object_version: {"sse": ssec} if ssec else None,
            test_get_object: {"sse": ssec} if ssec else None,
            test_get_object_version: {"sse": ssec} if ssec else None,
            test_list_objects: None,
            test_remove_incomplete_upload: None,
            test_presigned_get_object_default_expiry: None,
            test_presigned_put_object_default_expiry: None,
            test_presigned_post_policy: None,
            test_copy_object_no_copy_condition: {
                "ssec_copy": ssec, "ssec": ssec} if ssec else None,
            test_select_object_content: None,
            test_get_bucket_policy: None,
            test_set_bucket_policy_readonly: None,
            test_get_bucket_notification: None,
        }

    tests.update(
        {
            test_remove_object: None,
            test_remove_object_version: None,
            test_remove_objects: None,
            test_remove_object_versions: None,
            test_remove_bucket: None,
        },
    )

    for test_name, arg_list in tests.items():
        args = ()
        kwargs = {}
        _call_test(test_name, *args, **kwargs)

        if arg_list:
            args = ()
            kwargs = arg_list
            _call_test(test_name, *args, **kwargs)

    # Remove temporary files.
    if not is_mint_env:
        os.remove(_TEST_FILE)
        os.remove(_LARGE_FILE)


if __name__ == "__main__":
    try:
        main()
    except TestFailed:
        sys.exit(1)
    except Exception as exc:  # pylint: disable=broad-except
        print(exc)
        sys.exit(-1)
