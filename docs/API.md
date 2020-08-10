# Python Client API Reference [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io)

## Initialize MinIO Client object.

## MinIO

```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio(
	'play.min.io',
	access_key='Q3AM3UQ867SPQQA43P2F',
	secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
	secure=True,
)
```

## AWS S3

```py
from minio import Minio
from minio.error import ResponseError

s3Client = Minio(
	's3.amazonaws.com',
	access_key='YOUR-ACCESSKEYID',
	secret_key='YOUR-SECRETACCESSKEY',
	secure=True,
)
```

| Bucket operations                                         | Object operations                                       | Presigned operations                              | Bucket policy/notification/encryption operations                    |
|:----------------------------------------------------------|:--------------------------------------------------------|:--------------------------------------------------|:--------------------------------------------------------------------|
| [`make_bucket`](#make_bucket)                             | [`get_object`](#get_object)                             | [`presigned_get_object`](#presigned_get_object)   | [`get_bucket_policy`](#get_bucket_policy)                           |
| [`list_buckets`](#list_buckets)                           | [`put_object`](#put_object)                             | [`presigned_put_object`](#presigned_put_object)   | [`set_bucket_policy`](#set_bucket_policy)                           |
| [`bucket_exists`](#bucket_exists)                         | [`copy_object`](#copy_object)                           | [`presigned_post_policy`](#presigned_post_policy) | [`delete_bucket_policy`](#delete_bucket_policy)                     |
| [`remove_bucket`](#remove_bucket)                         | [`stat_object`](#stat_object)                           |                                                   | [`get_bucket_notification`](#get_bucket_notification)               |
| [`list_objects`](#list_objects)                           | [`remove_object`](#remove_object)                       |                                                   | [`set_bucket_notification`](#set_bucket_notification)               |
| [`list_objects_v2`](#list_objects_v2)                     | [`remove_objects`](#remove_objects)                     |                                                   | [`remove_all_bucket_notification`](#remove_all_bucket_notification) |
| [`list_incomplete_uploads`](#list_incomplete_uploads)     | [`remove_incomplete_upload`](#remove_incomplete_upload) |                                                   | [`listen_bucket_notification`](#listen_bucket_notification)         |
| [`enable_bucket_versioning`](#enable_bucket_versioning)   | [`fput_object`](#fput_object)                           |                                                   | [`get_bucket_encryption`](#get_bucket_encryption)                   |
| [`disable_bucket_versioning`](#disable_bucket_versioning) | [`fget_object`](#fget_object)                           |                                                   | [`put_bucket_encryption`](#put_bucket_encryption)                   |
|                                                           | [`select_object_content`](#select_object_content)       |                                                   | [`delete_bucket_encryption`](#delete_bucket_encryption)             |

## 1. Constructor

<a name="MinIO"></a>

### Minio(endpoint, access_key=None, secret_key=None, session_token=None, secure=True, region=None, http_client=None, credentials=None)
|                                                                                                                                       |
|---------------------------------------------------------------------------------------------------------------------------------------|
| `Minio(endpoint, access_key=None, secret_key=None, session_token=None, secure=True, region=None, http_client=None, credentials=None)` |
| Initializes a new client object.                                                                                                      |

__Parameters__

| Param           | Type                              | Description                                                                      |
|:----------------|:----------------------------------|:---------------------------------------------------------------------------------|
| `endpoint`      | _str_                             | Hostname of a S3 service.                                                        |
| `access_key`    | _str_                             | (Optional) Access key (aka user ID) of your account in S3 service.               |
| `secret_key`    | _str_                             | (Optional) Secret Key (aka password) of your account in S3 service.              |
| `session_token` | _str_                             | (Optional) Session token of your account in S3 service.                          |
| `secure`        | _bool_                            | (Optional) Flag to indicate to use secure (TLS) connection to S3 service or not. |
| `region`        | _str_                             | (Optional) Region name of buckets in S3 service.                                 |
| `http_client`   | _urllib3.poolmanager.PoolManager_ | (Optional) Customized HTTP client.                                               |
| `credentials`   | _minio.credentials.Credentials_   | (Optional) Credentials of your account in S3 service.                            |


**NOTE on concurrent usage:** The `Minio` object is thread safe when using the Python `threading` library. Specifically, it is **NOT** safe to share it between multiple processes, for example when using `multiprocessing.Pool`. The solution is simply to create a new `Minio` object in each process, and not share it between processes.

__Example__

### MinIO

```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio(
	'play.min.io',
	access_key='Q3AM3UQ867SPQQA43P2F',
	secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
)
```

> NOTE: If there is a corporate proxy, specify a custom httpClient using *urllib3.ProxyManager* as shown below:

```py
from minio import Minio
from minio.error import ResponseError
import urllib3

httpClient = urllib3.ProxyManager(
	'https://proxy_host.sampledomain.com:8119/',
	timeout=urllib3.Timeout.DEFAULT_TIMEOUT,
	cert_reqs='CERT_REQUIRED',
	retries=urllib3.Retry(
		total=5,
		backoff_factor=0.2,
		status_forcelist=[500, 502, 503, 504],
	)
)

minioClient = Minio(
	'your_hostname.sampledomain.com:9000',
	access_key='ACCESS_KEY',
	secret_key='SECRET_KEY',
	secure=True,
	http_client=httpClient,
)
```

### AWS S3

```py
from minio import Minio
from minio.error import ResponseError

s3Client = Minio(
	's3.amazonaws.com',
	access_key='ACCESS_KEY',
	secret_key='SECRET_KEY',
)
```

## 2. Bucket operations

<a name="make_bucket"></a>

### make_bucket(self, bucket_name, location='us-east-1', object_lock=False)

Create a bucket with region and object lock.

__Parameters__

| Param         | Type   | Description                                 |
|---------------|--------|---------------------------------------------|
| `bucket_name` | _str_  | Name of the bucket.                         |
| `location`    | _str_  | Region in which the bucket will be created. |
| `object_lock` | _bool_ | Flag to set object-lock feature.            |

__Example__

```py
minio.make_bucket('foo')
minio.make_bucket('foo', 'us-west-1')
minio.make_bucket('foo', 'us-west-1', object_lock=True)
```

<a name="list_buckets"></a>

### list_buckets()

List information of all accessible buckets.

__Parameters__

| Return                                   |
|:-----------------------------------------|
| An iterator contains bucket information. |

__Example__

```py
bucket_list = minio.list_buckets()
for bucket in bucket_list:
    print(bucket.name, bucket.created_date)
```

<a name="bucket_exists"></a>

### bucket_exists(bucket_name)

Check if a bucket exists.

__Parameters__

| Param         | Type  | Description         |
|:--------------|:------|:--------------------|
| `bucket_name` | _str_ | Name of the bucket. |

__Example__

```py
found = minio.bucket_exists("my-bucketname")
if found:
    print("my-bucketname exists")
else:
    print("my-bucketname does not exist")
```

<a name="remove_bucket"></a>

### remove_bucket(bucket_name)

Remove an empty bucket.

__Parameters__

| Param         | Type  | Description         |
|:--------------|:------|:--------------------|
| `bucket_name` | _str_ | Name of the bucket. |

__Example__

```py
minio.remove_bucket("my-bucketname")
```

<a name="list_objects"></a>

### list_objects(bucket_name, prefix=None, recursive=False, include_version=False)

Lists object information of a bucket using S3 API version 1, optionally for prefix recursively.

__Parameters__

| Param             | Type   | Description                                          |
|:------------------|:-------|:-----------------------------------------------------|
| `bucket_name`     | _str_  | Name of the bucket.                                  |
| `prefix`          | _str_  | Object name starts with prefix.                      |
| `recursive`       | _bool_ | List recursively than directory structure emulation. |
| `include_version` | _bool_ | Flag to control whether include object versions.     |

__Return Value__

| Return                                                    |
|:----------------------------------------------------------|
| An iterator contains object information as _minio.Object_ |

__Example__

```py
# List objects information.
objects = minio.list_objects('foo')
for object in objects:
    print(object)

# List objects information those names starts with 'hello/'.
objects = minio.list_objects('foo', prefix='hello/')
for object in objects:
    print(object)

# List objects information recursively.
objects = minio.list_objects('foo', recursive=True)
for object in objects:
    print(object)

# List objects information recursively those names starts with
# 'hello/'.
objects = minio.list_objects(
    'foo', prefix='hello/', recursive=True,
)
for object in objects:
    print(object)
```

<a name="list_objects_v2"></a>

### list_objects_v2(bucket_name, prefix=None, recursive=False, start_after=None, include_user_meta=False, include_version=False)

Lists object information of a bucket using S3 API version 2, optionally for prefix recursively.

__Parameters__

| Param               | Type   | Description                                              |
|:--------------------|:-------|:---------------------------------------------------------|
| `bucket_name`       | _str_  | Name of the bucket.                                      |
| `prefix`            | _str_  | Object name starts with prefix.                          |
| `recursive`         | _bool_ | List recursively than directory structure emulation.     |
| `start_after`       | _str_  | List objects after this key name.                        |
| `include_user_meta` | _bool_ | MinIO specific flag to control to include user metadata. |
| `include_version`   | _bool_ | Flag to control whether include object versions.         |

__Return Value__

| Return                                                    |
|:----------------------------------------------------------|
| An iterator contains object information as _minio.Object_ |

__Example__

```py
# List objects information.
objects = minio.list_objects_v2('foo')
for object in objects:
    print(object)

# List objects information those names starts with 'hello/'.
objects = minio.list_objects_v2('foo', prefix='hello/')
for object in objects:
    print(object)

# List objects information recursively.
objects = minio.list_objects_v2('foo', recursive=True)
for object in objects:
    print(object)

# List objects information recursively those names starts with
# 'hello/'.
objects = minio.list_objects_v2(
    'foo', prefix='hello/', recursive=True,
)
for object in objects:
    print(object)

# List objects information recursively after object name
# 'hello/world/1'.
objects = minio.list_objects_v2(
    'foo', recursive=True, start_after='hello/world/1',
)
for object in objects:
    print(object)
```

<a name="list_incomplete_uploads"></a>

### list_incomplete_uploads(bucket_name, prefix='', recursive=False)

List incomplete object upload information of a bucket, optionally for prefix recursively.

__Parameters__

| Param         | Type   | Description                                          |
|:--------------|:-------|:-----------------------------------------------------|
| `bucket_name` | _str_  | Name of the bucket.                                  |
| `prefix`      | _str_  | Object name starts with prefix.                      |
| `recursive`   | _bool_ | List recursively than directory structure emulation. |

__Return Value__

| Return                                                              |
|:--------------------------------------------------------------------|
| An iterator contains object information as _minio.IncompleteUpload_ |

__Example__

```py
# List incomplete object upload information.
objects = minio.list_incomplete_uploads('foo')
for object in objects:
    print(object)

# List incomplete object upload information those names starts with
# 'hello/'.
objects = minio.list_incomplete_uploads('foo', prefix='hello/')
for object in objects:
    print(object)

# List incomplete object upload information recursively.
objects = minio.list_incomplete_uploads('foo', recursive=True)
for object in objects:
    print(object)

# List incomplete object upload information recursively those names
# starts with 'hello/'.
objects = minio.list_incomplete_uploads(
    'foo', prefix='hello/', recursive=True,
)
for object in objects:
    print(object)
```

<a name="get_bucket_policy"></a>

### get_bucket_policy(bucket_name)

Get bucket policy configuration of a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Return Value__

| Param                                       |
|:--------------------------------------------|
| Bucket policy configuration as JSON string. |

__Example__

```py
config = minio.get_bucket_policy("my-bucketname")
```

<a name="set_bucket_policy"></a>

### set_bucket_policy(bucket_name, policy)

Set bucket policy configuration to a bucket.

__Parameters__

| Param           | Type  | Description                                 |
|:----------------|:------|:--------------------------------------------|
| ``bucket_name`` | _str_ | Name of the bucket.                         |
| ``Policy``      | _str_ | Bucket policy configuration as JSON string. |

__Example__

```py
minio.get_bucket_policy("my-bucketname", config)
```

<a name="delete_bucket_policy"></a>

### delete_bucket_policy(bucket_name)

Delete bucket policy configuration of a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Example__

```py
minio.delete_bucket_policy("my-bucketname")
```

<a name="get_bucket_notification"></a>

### get_bucket_notification(bucket_name)

Get notification configuration of a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Return Value__

| Param                                 |
|:--------------------------------------|
| Notification configuration as _dict_. |

__Example__

```py
config = minio.get_bucket_notification("my-bucketname")
```

<a name="set_bucket_notification"></a>

### set_bucket_notification(bucket_name, notification)

Set notification configuration of a bucket.

__Parameters__

| Param            | Type   | Description                                              |
|:-----------------|:-------|:---------------------------------------------------------|
| ``bucket_name``  | _str_  | Name of the bucket.                                      |
| ``notification`` | _dict_ | Non-empty dictionary with the structure specified below. |

The `notification` argument has the following structure:

* (dict) --
  * __TopicConfigurations__ (list) -- Optional list of service
    configuration items specifying AWS SNS Topics as the target of the
    notification.
  * __QueueConfigurations__ (list) -- Optional list of service
    configuration items specifying AWS SQS Queues as the target of the
    notification.
  * __CloudFunctionconfigurations__ (list) -- Optional list of service
    configuration items specifying AWS Lambda Cloud functions as the
    target of the notification.

At least one of the above items needs to be specified in the
`notification` argument.

The "service configuration item" alluded to above has the following structure:

* (dict) --
  * __Id__ (string) -- Optional Id for the configuration item. If not
    specified, it is auto-generated by the server.
  * __Arn__ (string) -- Specifies the particular Topic/Queue/Cloud
    Function identifier.
  * __Events__ (list) -- A non-empty list of event-type strings from:
      _'s3:ReducedRedundancyLostObject'_,
      _'s3:ObjectCreated:*'_,
      _'s3:ObjectCreated:Put'_,
      _'s3:ObjectCreated:Post'_,
      _'s3:ObjectCreated:Copy'_,
      _'s3:ObjectCreated:CompleteMultipartUpload'_,
      _'s3:ObjectRemoved:*'_,
      _'s3:ObjectRemoved:Delete'_,
      _'s3:ObjectRemoved:DeleteMarkerCreated'_
  * __Filter__ (dict) -- An optional dictionary container of object
    key name based filter rules.
    * __Key__ (dict) -- Dictionary container of object key name prefix
      and suffix filtering rules.
      * __FilterRules__ (list) -- A list of containers that specify
        the criteria for the filter rule.
        * (dict) -- A dictionary container of key value pairs that
          specify a single filter rule.
          * __Name__ (string) -- Object key name with value 'prefix'
            or 'suffix'.
          * __Value__ (string) -- Specify the value of the
            prefix/suffix to which the rule applies.

__Example__

```py
config = {
    'QueueConfigurations': [
        {
            'Id': '1',
            'Arn': 'arn1',
            'Events': ['s3:ObjectCreated:*'],
            'Filter': {
                'Key': {
                    'FilterRules': [
                        {
                            'Name': 'prefix',
                            'Value': 'abc'
                        }
                    ]
                }
            }
        }
    ],
    'TopicConfigurations': [
        {
            'Arn': 'arn2',
            'Events': ['s3:ObjectCreated:*'],
            'Filter': {
                'Key': {
                    'FilterRules': [
                        {
                            'Name': 'suffix',
                            'Value': '.jpg'
                        }
                    ]
                }
            }
        }
    ],
    'CloudFunctionConfigurations': [
        {
            'Arn': 'arn3',
            'Events': ['s3:ObjectRemoved:*'],
            'Filter': {
                'Key': {
                    'FilterRules': [
                        {
                            'Name': 'suffix',
                            'Value': '.jpg'
                        }
                    ]
                }
            }
        }
    ]
}

minio.set_bucket_notification("my-bucketname", config)
```

<a name="remove_all_bucket_notification"></a>

### remove_all_bucket_notification(bucket_name)

Remove notification configuration of a bucket. On success, S3 service stops notification of events previously set of the bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Example__

```py
minio.remove_all_bucket_notification("my-bucketname")
```

<a name="listen_bucket_notification"></a>

### listen_bucket_notification(bucket_name, prefix='', suffix='', events=('s3:ObjectCreated:*', 's3:ObjectRemoved:*', 's3:ObjectAccessed:*'))

Listen events of object prefix and suffix of a bucket. Caller should iterate returned iterator to read new events.

__Parameters__

| Param         | Type   | Description                                 |
|:--------------|:-------|:--------------------------------------------|
| `bucket_name` | _str_  | Name of the bucket.                         |
| `prefix`      | _str_  | Listen events of object starts with prefix. |
| `suffix`      | _str_  | Listen events of object ends with suffix.   |
| `events`      | _list_ | Events to listen.                           |

```py
iter = minio.listen_bucket_notification(
    "my-bucketname",
    events=('s3:ObjectCreated:*', 's3:ObjectAccessed:*'),
)
for events in iter:
    print(events)
```

<a name="get_bucket_encryption"></a>

### get_bucket_encryption(bucket_name)

Get encryption configuration of a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Return Value__

| Param                               |
|:------------------------------------|
| Encryption configuration as _dict_. |

__Example__

```py
config = minio.get_bucket_encryption("my-bucketname")
```

<a name="put_bucket_encryption"></a>

### put_bucket_encryption(bucket_name, encryption_configuration)

Set encryption configuration of a bucket.

__Parameters__

| Param           | Type   | Description                                       |
|:----------------|:-------|:--------------------------------------------------|
| ``bucket_name`` | _str_  | Name of the bucket.                               |
| ``enc_config``  | _dict_ | Encryption configuration as dictionary to be set. |

__Example__

```py
# Sample default encryption configuration
config = {
    'ServerSideEncryptionConfiguration':{
        'Rule': [
            {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}
        ]
    }
}

minio.put_bucket_encryption("my-bucketname", config)
```

<a name="delete_bucket_encryption"></a>

### delete_bucket_encryption(bucket_name)

Delete encryption configuration of a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Example__

```py
minio.delete_bucket_encryption("my-bucketname")
```

<a name="enable_bucket_versioning"></a>

### enable_bucket_versioning(bucket_name)

Enable object versioning feature in a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Example__

```py
minio.enable_bucket_versioning("my-bucketname")
```

<a name="enable_bucket_versioning"></a>

### disable_bucket_versioning(bucket_name)

Disable object versioning feature in a bucket.

__Parameters__

| Param           | Type  | Description         |
|:----------------|:------|:--------------------|
| ``bucket_name`` | _str_ | Name of the bucket. |

__Example__

```py
minio.disable_bucket_versioning("my-bucketname")
```

## 3. Object operations

<a name="get_object"></a>

### get_object(bucket_name, object_name, offset=0, length=0, request_headers=None, sse=None, version_id=None, extra_query_params=None)

Gets data from offset to length of an object. Returned response should be closed after use to release network resources. To reuse the connection, its required to call `response.release_conn()` explicitly.

__Parameters__

| Param                | Type             | Description                                          |
|:---------------------|:-----------------|:-----------------------------------------------------|
| `bucket_name`        | _str_            | Name of the bucket.                                  |
| `object_name`        | _str_            | Object name in the bucket.                           |
| `offset`             | _int_            | Start byte position of object data.                  |
| `length`             | _int_            | Number of bytes of object data from offset.          |
| `request_headers`    | _dict_           | Any additional headers to be added with GET request. |
| `sse`                | _SseCustomerKey_ | Server-side encryption customer key.                 |
| `version_id`         | _str_            | Version-ID of the object.                            |
| `extra_query_params` | _dict_           | Extra query parameters for advanced usage.           |

__Return Value__

| Return                                  |
|:----------------------------------------|
| _urllib3.response.HTTPResponse_ object. |

__Example__

```py
// Get entire object data.
 try:
    response = minio.get_object('foo', 'bar')
    // Read data from response.
finally:
    response.close()
    response.release_conn()

// Get object data for offset/length.
try:
    response = minio.get_partial_object('foo', 'bar', 2, 4)
    // Read data from response.
finally:
    response.close()
    response.release_conn()
```

<a name="select_object_content"></a>

### select_object_content(bucket_name, object_name, opts)

Select content of an object by SQL expression.

__Parameters__

| Param         | Type                  | Description                |
|:--------------|:----------------------|:---------------------------|
| `bucket_name` | _str_                 | Name of the bucket.        |
| `object_name` | _str_                 | Object name in the bucket. |
| `opts`        | _SelectObjectOptions_ | Options for select object. |

__Return Value__

| Return                                                                               |
|:-------------------------------------------------------------------------------------|
| A reader contains requested records and progress information as _SelectObjectReader_ |

__Example__

```py
options = SelectObjectOptions(
    expression=" select * from s3object",
    input_serialization=InputSerialization(
        compression_type="NONE",
        csv=CSVInput(file_header_info="USE",
                     record_delimiter="\n",
                     field_delimiter=",",
                     quote_character='"',
                     quote_escape_character='"',
                     comments="#",
                     allow_quoted_record_delimiter="FALSE",
                     ),
        ),

    output_serialization=OutputSerialization(
        csv=CSVOutput(quote_fields="ASNEEDED",
                      record_delimiter="\n",
                      field_delimiter=",",
                      quote_character='"',
                      quote_escape_character='"',)
                      ),
    request_progress=RequestProgress(
        enabled="FALSE"
        )
    )

data = client.select_object_content('my-bucket', 'my-object', options)
# Get the records
with open('my-record-file', 'w') as record_data:
	for d in data.stream(10*1024):
		record_data.write(d)

	# Get the stats
	print(data.stats())
```

<a name="fget_object"></a>

### fget_object(bucket_name, object_name, file_path, request_headers=None, sse=None, version_id=None, extra_query_params=None)

Downloads data of an object to file.

__Parameters__

| Param                | Type             | Description                                          |
|:---------------------|:-----------------|:-----------------------------------------------------|
| `bucket_name`        | _str_            | Name of the bucket.                                  |
| `object_name`        | _str_            | Object name in the bucket.                           |
| `file_path`          | _str_            | Name of file to upload.                              |
| `request_headers`    | _dict_           | Any additional headers to be added with GET request. |
| `sse`                | _SseCustomerKey_ | Server-side encryption customer key.                 |
| `version_id`         | _str_            | Version-ID of the object.                            |
| `extra_query_params` | _dict_           | Extra query parameters for advanced usage.           |

__Return Value__

| Return                         |
|:-------------------------------|
| Object information as _Object_ |

__Example__

```py
minio.fget_object('foo', 'bar', 'localfile')
minio.fget_object(
    'foo', 'bar', 'localfile', version_id='VERSION-ID',
)
```

<a name="copy_object"></a>

### copy_object(bucket_name, object_name, object_source, conditions=None, source_sse=None, sse=None, metadata=None)

Create an object by server-side copying data from another object. In this API maximum supported source object size is 5GiB.

__Parameters__

| Param           | Type             | Description                                                           |
|:----------------|:-----------------|:----------------------------------------------------------------------|
| `bucket_name`   | _str_            | Name of the bucket.                                                   |
| `object_name`   | _str_            | Object name in the bucket.                                            |
| `object_source` | _str_            | Source object to be copied.                                           |
| `conditions`    | _CopyConditions_ | Collection of supported CopyObject conditions.                        |
| `source_sse`    | _SseCustomerKey_ | Server-side encryption customer key of source object.                 |
| `sse`           | _Sse_            | Server-side encryption of destination object.                         |
| `metadata`      | _dict_           | Any user-defined metadata to be copied along with destination object. |

__Return Value__

| Return             |
|:-------------------|
| _CopyObjectResult_ |

__Example__

```py
import time
from datetime import datetime
from minio import CopyConditions

minio.copy_object(
    "my-bucketname",
    "my-objectname",
    "my-source-bucketname/my-source-bucketname",
)

minio.copy_object(
    "my-bucketname",
    "my-objectname",
    "my-source-bucketname/my-source-bucketname"
    "?versionId=b6602757-7c9c-449b-937f-fed504d04c94",
)

copy_conditions = CopyConditions()
# Set modified condition, copy object modified since 2014 April.
t = (2014, 4, 0, 0, 0, 0, 0, 0, 0)
mod_since = datetime.utcfromtimestamp(time.mktime(t))
copy_conditions.set_modified_since(mod_since)

# Set unmodified condition, copy object unmodified since 2014 April.
copy_conditions.set_unmodified_since(mod_since)

# Set matching ETag condition, copy object which matches the following ETag.
copy_conditions.set_match_etag("31624deb84149d2f8ef9c385918b653a")

# Set matching ETag except condition, copy object which does not match the following ETag.
copy_conditions.set_match_etag_except("31624deb84149d2f8ef9c385918b653a")

# Set metadata, which will be copied along with the destination object.
metadata = {"test-key": "test-data"}

result = minioClient.copy_object(
	"mybucket",
	"myobject",
	"/my-sourcebucketname/my-sourceobjectname",
	copy_conditions,metadata=metadata,
)
print(result)
```

<a name="put_object"></a>

### put_object(bucket_name, object_name, data, length, content_type='application/octet-stream', metadata=None, sse=None, progress=None, part_size=DEFAULT_PART_SIZE)

Uploads data from a stream to an object in a bucket.

__Parameters__

| Param          | Type           | Description                                                         |
|:---------------|:---------------|:--------------------------------------------------------------------|
| `bucket_name`  | _str_          | Name of the bucket.                                                 |
| `object_name`  | _str_          | Object name in the bucket.                                          |
| `data`         | _io.RawIOBase_ | Contains object data.                                               |
| `content_type` | _str_          | Content type of the object.                                         |
| `metadata`     | _dict_         | Any additional metadata to be uploaded along with your PUT request. |
| `sse`          | _Sse_          | Server-side encryption.                                             |
| `progress`     | _threading_    | A progress object.                                                  |
| `part_size`    | _int_          | Multipart part size.                                                |

__Return Value__

| Return                            |
|:----------------------------------|
| etag and version ID if available. |

__Example__
```py
file_stat = os.stat('hello.txt')
with open('hello.txt', 'rb') as data:
    minio.put_object(
        'foo', 'bar', data, file_stat.st_size, 'text/plain',
    )
```

<a name="fput_object"></a>

### fput_object(bucket_name, object_name, file_path, content_type='application/octet-stream', metadata=None, sse=None, progress=None, part_size=DEFAULT_PART_SIZE)

Uploads data from a file to an object in a bucket.

| Param          | Type        | Description                                                         |
|:---------------|:------------|:--------------------------------------------------------------------|
| `bucket_name`  | _str_       | Name of the bucket.                                                 |
| `object_name`  | _str_       | Object name in the bucket.                                          |
| `file_path`    | _str_       | Name of file to upload.                                             |
| `content_type` | _str_       | Content type of the object.                                         |
| `metadata`     | _dict_      | Any additional metadata to be uploaded along with your PUT request. |
| `sse`          | _Sse_       | Server-side encryption.                                             |
| `progress`     | _threading_ | A progress object.                                                  |
| `part_size`    | _int_       | Multipart part size.                                                |

__Return Value__

| Return                            |
|:----------------------------------|
| etag and version ID if available. |

__Example__

```py
minio.fput_object('foo', 'bar', 'filepath', 'text/plain')
```

<a name="stat_object"></a>

### stat_object(bucket_name, object_name, sse=None, version_id=None, extra_query_params=None)

Get object information and metadata of an object.

__Parameters__

| Param                | Type             | Description                                |
|:---------------------|:-----------------|:-------------------------------------------|
| `bucket_name`        | _str_            | Name of the bucket.                        |
| `object_name`        | _str_            | Object name in the bucket.                 |
| `sse`                | _SseCustomerKey_ | Server-side encryption customer key.       |
| `version_id`         | _str_            | Version ID of the object.                  |
| `extra_query_params` | _dict_           | Extra query parameters for advanced usage. |

__Return Value__

| Return   |
|:---------|
| Object information as _Object_ |

__Example__

```py
stat = minio.stat_object("my-bucketname", "my-objectname")
```

<a name="remove_object"></a>

### remove_object(bucket_name, object_name, version_id=None)

Remove an object.

__Parameters__

| Param         | Type  | Description                |
|:--------------|:------|:---------------------------|
| `bucket_name` | _str_ | Name of the bucket.        |
| `object_name` | _str_ | Object name in the bucket. |
| `version_id`  | _str_ | Version ID of the object.  |

__Example__

```py
minio.remove_object("my-bucketname", "my-objectname")
minio.remove_object(
    "my-bucketname",
    "my-objectname",
    version_id="13f88b18-8dcd-4c83-88f2-8631fdb6250c",
)
```

<a name="remove_objects"></a>

### remove_objects(bucket_name, objects_iter)

Remove multiple objects.

__Parameters__

| Param          | Type   | Description                                                         |
|:---------------|:-------|:--------------------------------------------------------------------|
| `bucket_name`  | _str_  | Name of the bucket.                                                 |
| `objects_iter` | _list_ | An iterable type python object providing object names for deletion. |

__Return Value__

| Return                                  |
|:----------------------------------------|
| An iterator contains _MultiDeleteError_ |

__Example__

```py
minio.remove_objects(
    "my-bucketname",
    [
        "my-objectname1",
        "my-objectname2",
        ("my-objectname3", "13f88b18-8dcd-4c83-88f2-8631fdb6250c"),
    ],
)
```

<a name="remove_incomplete_upload"></a>

### remove_incomplete_upload(bucket_name, object_name)

Remove all incomplete uploads of an object.

__Parameters__

| Param         | Type  | Description                |
|:--------------|:------|:---------------------------|
| `bucket_name` | _str_ | Name of the bucket.        |
| `object_name` | _str_ | Object name in the bucket. |

__Example__

```py
minio.remove_incomplete_upload("my-bucketname", "my-objectname")
```

## 4. Presigned operations

<a name="presigned_get_object"></a>

### presigned_get_object(bucket_name, object_name, expires=timedelta(days=7), response_headers=None, request_date=None, version_id=None, extra_query_params=None)

Get presigned URL of an object to download its data with expiry time and custom request parameters.

__Parameters__

| Param                | Type                 | Description                                                                                                          |
|:---------------------|:---------------------|:---------------------------------------------------------------------------------------------------------------------|
| `bucket_name`        | _str_                | Name of the bucket.                                                                                                  |
| `object_name`        | _str_                | Object name in the bucket.                                                                                           |
| `expires`            | _datetime.timedelta_ | Expiry in seconds; defaults to 7 days.                                                                               |
| `response_headers`   | _dict_               | Optional response_headers argument to specify response fields like date, size, type of file, data about server, etc. |
| `request_date`       | _datetime.datetime_  | Optional request_date argument to specify a different request date. Default is current date.                         |
| `version_id`         | _str_                | Version ID of the object.                                                                                            |
| `extra_query_params` | _dict_               | Extra query parameters for advanced usage.                                                                           |

__Return Value__

| Return     |
|:-----------|
| URL string |

__Example__

```py
# Get presigned URL string to download 'my-objectname' in
# 'my-bucketname' with default expiry.
url = minio.presigned_get_object("my-bucketname", "my-objectname")
print(url)

# Get presigned URL string to download 'my-objectname' in
# 'my-bucketname' with two hours expiry.
url = minio.presigned_get_object(
    "my-bucketname", "my-objectname", expires=timedelta(hours=2),
)
print(url)
```

<a name="presigned_put_object"></a>

### presigned_put_object(bucket_name, object_name, expires=timedelta(days=7))

Get presigned URL of an object to upload data with expiry time and custom request parameters.

__Parameters__

| Param         | Type                 | Description                            |
|:--------------|:---------------------|:---------------------------------------|
| `bucket_name` | _str_                | Name of the bucket.                    |
| `object_name` | _str_                | Object name in the bucket.             |
| `expires`     | _datetime.timedelta_ | Expiry in seconds; defaults to 7 days. |

__Return Value__

| Return     |
|:-----------|
| URL string |

__Example__

```py
# Get presigned URL string to upload data to 'my-objectname' in
# 'my-bucketname' with default expiry.
url = minio.presigned_put_object("my-bucketname", "my-objectname")
print(url)

# Get presigned URL string to upload data to 'my-objectname' in
# 'my-bucketname' with two hours expiry.
url = minio.presigned_put_object(
    "my-bucketname", "my-objectname", expires=timedelta(hours=2),
)
print(url)
```

<a name="presigned_post_policy"></a>

### presigned_post_policy(post_policy)

Get form-data of PostPolicy of an object to upload its data using POST method.

__Parameters__

| Param         | Type         | Description  |
|:--------------|:-------------|:-------------|
| `post_policy` | _PostPolicy_ | Post policy. |

__Return Value__

| Return                      |
|:----------------------------|
| Form-data containing _dict_ |

__Example__

Create policy:

```py
post_policy = PostPolicy()
post_policy.set_bucket_name('bucket_name')

# set object prefix for object upload.
post_policy.set_key_startswith('objectPrefix/')

# set expiry to 10 days.
expires_date = datetime.utcnow()+timedelta(days=10)
post_policy.set_expires(expires_date)

# set content length for incoming uploads.
post_policy.set_content_length_range(10, 1024)

# set content-type to allow only text.
post_policy.set_content_type('text/plain')

form_data = presigned_post_policy(post_policy)
print(form_data)
```

## 5. Explore Further

- [MinIO Golang Client SDK Quickstart Guide](https://docs.min.io/docs/golang-client-quickstart-guide)
- [MinIO Java Client SDK Quickstart Guide](https://docs.min.io/docs/java-client-quickstart-guide)
- [MinIO JavaScript Client SDK Quickstart Guide](https://docs.min.io/docs/javascript-client-quickstart-guide)
