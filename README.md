# MinIO Python Library for Amazon S3 Compatible Cloud Storage [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io)

The MinIO Python Client SDK provides simple APIs to access any Amazon S3 compatible object storage server.

This quickstart guide will show you how to install the client SDK and execute an example python program. For a complete list of APIs and examples, please take a look at the [Python Client API Reference](https://docs.min.io/docs/python-client-api-reference) documentation.

This document assumes that you have a working [Python](https://www.python.org/downloads/) setup in place.

## Minimum Requirements

- Python 2.7 or higher

## Download from pip

```sh
pip install minio
```

## Download from pip3

```sh
pip3 install minio
```

## Download from source

```sh
git clone https://github.com/minio/minio-py
cd minio-py
python setup.py install
```

## Initialize MinIO Client

You need four items in order to connect to MinIO object storage server.

| Params     | Description |
| :------- | :---- |
| endpoint | URL to object storage service. |
| access_key| Access key is like user ID that uniquely identifies your account.   |
| secret_key| Secret key is the password to your account.    |
|secure|Set this value to 'True' to enable secure (HTTPS) access.|

```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio('play.min.io',
                  access_key='Q3AM3UQ867SPQQA43P2F',
                  secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
                  secure=True)
```


## Quick Start Example - File Uploader
This example program connects to a MinIO object storage server, makes a bucket on the server and then uploads a file to the bucket.

We will use the MinIO server running at [https://play.min.io](https://play.min.io) in this example. Feel free to use this service for testing and development. Access credentials shown in this example are open to the public.

#### file-uploader.py

```py
# Import MinIO library.
from minio import Minio
from minio.error import (ResponseError, BucketAlreadyOwnedByYou,
                         BucketAlreadyExists)

# Initialize minioClient with an endpoint and access/secret keys.
minioClient = Minio('play.min.io',
                    access_key='Q3AM3UQ867SPQQA43P2F',
                    secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
                    secure=True)

# Make a bucket with the make_bucket API call.
try:
       minioClient.make_bucket("maylogs", location="us-east-1")
except BucketAlreadyOwnedByYou as err:
       pass
except BucketAlreadyExists as err:
       pass
except ResponseError as err:
       raise

# Put an object 'pumaserver_debug.log' with contents from 'pumaserver_debug.log'.
try:
       minioClient.fput_object('maylogs', 'pumaserver_debug.log', '/tmp/pumaserver_debug.log')
except ResponseError as err:
       print(err)
        
```

#### Run file-uploader

```bash
python file_uploader.py

mc ls play/maylogs/
[2016-05-27 16:41:37 PDT]  12MiB pumaserver_debug.log
```

## API Reference

The full API Reference is available here.
* [Complete API Reference](https://docs.min.io/docs/python-client-api-reference)

### API Reference : Bucket Operations

* [`make_bucket`](https://docs.min.io/docs/python-client-api-reference#make_bucket)
* [`list_buckets`](https://docs.min.io/docs/python-client-api-reference#list_buckets)
* [`bucket_exists`](https://docs.min.io/docs/python-client-api-reference#bucket_exists)
* [`remove_bucket`](https://docs.min.io/docs/python-client-api-reference#remove_bucket)
* [`list_objects`](https://docs.min.io/docs/python-client-api-reference#list_objects)
* [`list_objects_v2`](https://docs.min.io/docs/python-client-api-reference#list_objects_v2)
* [`list_incomplete_uploads`](https://docs.min.io/docs/python-client-api-reference#list_incomplete_uploads)

### API Reference : Bucket policy Operations

* [`get_bucket_policy`](https://docs.min.io/docs/python-client-api-reference#get_bucket_policy)
* [`set_bucket_policy`](https://docs.min.io/docs/python-client-api-reference#set_bucket_policy)

### API Reference : Bucket notification Operations

* [`set_bucket_notification`](https://docs.min.io/docs/python-client-api-reference#set_bucket_notification)
* [`get_bucket_notification`](https://docs.min.io/docs/python-client-api-reference#get_bucket_notification)
* [`remove_all_bucket_notification`](https://docs.min.io/docs/python-client-api-reference#remove_all_bucket_notification)
* [`listen_bucket_notification`](https://docs.min.io/docs/python-client-api-reference#listen_bucket_notification)

### API Reference : File Object Operations

* [`fput_object`](https://docs.min.io/docs/python-client-api-reference#fput_object)
* [`fget_object`](https://docs.min.io/docs/python-client-api-reference#fget_object)

### API Reference : Object Operations

* [`get_object`](https://docs.min.io/docs/python-client-api-reference#get_object)
* [`put_object`](https://docs.min.io/docs/python-client-api-reference#put_object)
* [`stat_object`](https://docs.min.io/docs/python-client-api-reference#stat_object)
* [`copy_object`](https://docs.min.io/docs/python-client-api-reference#copy_object)
* [`get_partial_object`](https://docs.min.io/docs/python-client-api-reference#get_partial_object)
* [`remove_object`](https://docs.min.io/docs/python-client-api-reference#remove_object)
* [`remove_objects`](https://docs.min.io/docs/python-client-api-reference#remove_objects)
* [`remove_incomplete_upload`](https://docs.min.io/docs/python-client-api-reference#remove_incomplete_upload)

### API Reference : Presigned Operations

* [`presigned_get_object`](https://docs.min.io/docs/python-client-api-reference#presigned_get_object)
* [`presigned_put_object`](https://docs.min.io/docs/python-client-api-reference#presigned_put_object)
* [`presigned_post_policy`](https://docs.min.io/docs/python-client-api-reference#presigned_post_policy)

## Full Examples

#### Full Examples : Bucket Operations

* [make_bucket.py](https://github.com/minio/minio-py/blob/master/examples/make_bucket.py)
* [list_buckets.py](https://github.com/minio/minio-py/blob/master/examples/list_buckets.py)
* [bucket_exists.py](https://github.com/minio/minio-py/blob/master/examples/bucket_exists.py)
* [list_objects.py](https://github.com/minio/minio-py/blob/master/examples/list_objects.py)
* [remove_bucket.py](https://github.com/minio/minio-py/blob/master/examples/remove_bucket.py)
* [list_incomplete_uploads.py](https://github.com/minio/minio-py/blob/master/examples/list_incomplete_uploads.py)

#### Full Examples : Bucket policy Operations

* [set_bucket_policy.py](https://github.com/minio/minio-py/blob/master/examples/set_bucket_policy.py)
* [get_bucket_policy.py](https://github.com/minio/minio-py/blob/master/examples/get_bucket_policy.py)

#### Full Examples: Bucket notification Operations

* [set_bucket_notification.py](https://github.com/minio/minio-py/blob/master/examples/set_bucket_notification.py)
* [get_bucket_notification.py](https://github.com/minio/minio-py/blob/master/examples/get_bucket_notification.py)
* [remove_all_bucket_notification.py](https://github.com/minio/minio-py/blob/master/examples/remove_all_bucket_notification.py)
* [listen_bucket_notification.py](https://github.com/minio/minio-py/blob/master/examples/listen_notification.py)

#### Full Examples : File Object Operations

* [fput_object.py](https://github.com/minio/minio-py/blob/master/examples/fput_object.py)
* [fget_object.py](https://github.com/minio/minio-py/blob/master/examples/fget_object.py)

#### Full Examples : Object Operations

* [get_object.py](https://github.com/minio/minio-py/blob/master/examples/get_object.py)
* [put_object.py](https://github.com/minio/minio-py/blob/master/examples/put_object.py)
* [stat_object.py](https://github.com/minio/minio-py/blob/master/examples/stat_object.py)
* [copy_object.py](https://github.com/minio/minio-py/blob/master/examples/copy_object.py)
* [get_partial_object.py](https://github.com/minio/minio-py/blob/master/examples/get_partial_object.py)
* [remove_object.py](https://github.com/minio/minio-py/blob/master/examples/remove_object.py)
* [remove_objects.py](https://github.com/minio/minio-py/blob/master/examples/remove_objects.py)
* [remove_incomplete_upload.py](https://github.com/minio/minio-py/blob/master/examples/remove_incomplete_upload.py)

#### Full Examples : Presigned Operations

* [presigned_get_object.py](https://github.com/minio/minio-py/blob/master/examples/presigned_get_object.py)
* [presigned_put_object.py](https://github.com/minio/minio-py/blob/master/examples/presigned_put_object.py)
* [presigned_post_policy.py](https://github.com/minio/minio-py/blob/master/examples/presigned_post_policy.py)

## Explore Further

* [Complete Documentation](https://docs.min.io)
* [MinIO Python SDK API Reference](https://docs.min.io/docs/python-client-api-reference)

## Contribute

[Contributors Guide](https://github.com/minio/minio-py/blob/master/CONTRIBUTING.md)

[![PYPI](https://img.shields.io/pypi/v/minio.svg)](https://pypi.python.org/pypi/minio)
[![Build Status](https://travis-ci.org/minio/minio-py.svg)](https://travis-ci.org/minio/minio-py)
[![Build status](https://ci.appveyor.com/api/projects/status/1d05e6nvxcelmrak?svg=true)](https://ci.appveyor.com/project/harshavardhana/minio-py)
