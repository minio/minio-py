# Python Client API Reference [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io)

## Initialize MinIO Client object.

## MinIO

```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio('play.min.io',
                  access_key='Q3AM3UQ867SPQQA43P2F',
                  secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
                  secure=True)
```

## AWS S3

```py
from minio import Minio
from minio.error import ResponseError

s3Client = Minio('s3.amazonaws.com',
                 access_key='YOUR-ACCESSKEYID',
                 secret_key='YOUR-SECRETACCESSKEY',
                 secure=True)
```



| Bucket operations                                     | Object operations                                       | Presigned operations                              | Bucket policy/notification operations                               |
|:------------------------------------------------------|:--------------------------------------------------------|:--------------------------------------------------|:--------------------------------------------------------------------|
| [`make_bucket`](#make_bucket)                         | [`get_object`](#get_object)                             | [`presigned_get_object`](#presigned_get_object)   | [`get_bucket_policy`](#get_bucket_policy)                           |
| [`list_buckets`](#list_buckets)                       | [`put_object`](#put_object)                             | [`presigned_put_object`](#presigned_put_object)   | [`set_bucket_policy`](#set_bucket_policy)                           |
| [`bucket_exists`](#bucket_exists)                     | [`copy_object`](#copy_object)                           | [`presigned_post_policy`](#presigned_post_policy) | [`get_bucket_notification`](#get_bucket_notification)               |
| [`remove_bucket`](#remove_bucket)                     | [`stat_object`](#stat_object)                           |                                                   | [`set_bucket_notification`](#set_bucket_notification)               |
| [`list_objects`](#list_objects)                       | [`remove_object`](#remove_object)                       |                                                   | [`remove_all_bucket_notification`](#remove_all_bucket_notification) |
| [`list_objects_v2`](#list_objects_v2)                 | [`remove_objects`](#remove_objects)                     |                                                   | [`listen_bucket_notification`](#listen_bucket_notification)         |
| [`list_incomplete_uploads`](#list_incomplete_uploads) | [`remove_incomplete_upload`](#remove_incomplete_upload) |                                                   |                                                                     |
|                                                       | [`fput_object`](#fput_object)                           |                                                   |                                                                     |
|                                                       | [`fget_object`](#fget_object)                           |                                                   |                                                                     |
|                                                       | [`get_partial_object`](#get_partial_object)             |                                                   |                                                                     |
|                                                       | [`select_object_content`](#select_object_content)       |                                                   |                                                                     |

## 1. Constructor

<a name="MinIO"></a>
### Minio(endpoint, access_key=None, secret_key=None, secure=True, region=None, http_client=None)

|   |
|---|
| `Minio(endpoint, access_key=None, secret_key=None, secure=True, region=None, http_client=None)`  |
| Initializes a new client object.  |

__Parameters__


| Param  |  Type | Description  |
|:---|:---|:---|
| `endpoint`  | _string_  | S3 object storage endpoint.  |
| `access_key`  | _string_  | Access key for the object storage endpoint. (Optional if you need anonymous access).  |
| `secret_key` | _string_  |  Secret key for the object storage endpoint. (Optional if you need anonymous access). |
| `secure`  |_bool_   | Set this value to `True` to enable secure (HTTPS) access. (Optional defaults to `True`).  |
| `region`  |_string_ | Set this value to override automatic bucket location discovery. (Optional defaults to `None`). |
| `http_client` |_urllib3.poolmanager.PoolManager_ | Set this value to use custom http client instead of using default http client. (Optional defaults to `None`) |

__Example__

### MinIO

```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio('play.min.io',
                    access_key='Q3AM3UQ867SPQQA43P2F',
                    secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
```

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
                    status_forcelist=[500, 502, 503, 504]
                )
            )
minioClient = Minio('your_hostname.sampledomain.com:9000',
                    access_key='ACCESS_KEY',
                    secret_key='SECRET_KEY',
                    secure=True,
                    http_client=httpClient)
```

### AWS S3

```py
from minio import Minio
from minio.error import ResponseError

s3Client = Minio('s3.amazonaws.com',
                 access_key='ACCESS_KEY',
                 secret_key='SECRET_KEY')
```

## 2. Bucket operations

<a name="make_bucket"></a>
### make_bucket(bucket_name, location='us-east-1')
Creates a new bucket.

__Parameters__

| Param  | Type  | Description  |
|---|---|---|
|`bucket_name`  | _string_  | Name of the bucket. |
| `location`  |  _string_ | Default value is us-east-1 Region where the bucket is created. Valid values are listed below: |
| | |us-east-1 |
| | |us-west-1 |
| | |us-west-2 |
| | |eu-west-1 |
| | | eu-central-1|
| | | ap-southeast-1|
| | | ap-southeast-2|
| | | ap-northeast-1|
| | | ap-northeast-2|
| | | sa-east-1|
| | | cn-north-1|

__Example__

```py
try:
    minioClient.make_bucket("mybucket", location="us-east-1")
except ResponseError as err:
    print(err)
```

<a name="list_buckets"></a>
### list_buckets()
Lists all buckets.

__Parameters__

|Return   |Type   |Description   |
|:---|:---|:---|
|``bucketList``   |_function_ |List of all buckets. |
|``bucket.name``   |_string_  |Bucket name. |
|``bucket.creation_date`` |_time_   |Time: date when bucket was created. |

__Example__

```py
buckets = minioClient.list_buckets()
for bucket in buckets:
    print(bucket.name, bucket.creation_date)
```

<a name="bucket_exists"></a>
### bucket_exists(bucket_name)
Checks if a bucket exists.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_|Name of the bucket. |

__Example__

```py
try:
    print(minioClient.bucket_exists("mybucket"))
except ResponseError as err:
    print(err)
```

<a name="remove_bucket"></a>
### remove_bucket(bucket_name)
Removes a bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_ |Name of the bucket. |

__Example__

```py
try:
    minioClient.remove_bucket("mybucket")
except ResponseError as err:
    print(err)
```

<a name="list_objects"></a>
### list_objects(bucket_name, prefix=None, recursive=False)
Lists objects in a bucket.

__Parameters__

| Param  |Type  | Description  |
|:---|:---|:---|
|``bucket_name`` | _string_ | Name of the bucket.  |
|``prefix``      | _string_ | The prefix of the objects that should be listed. Optional, default is None.|
|``recursive``   |  _bool_  |``True`` indicates recursive style listing and ``False`` indicates directory style listing delimited by '/'. Optional, default is False.   |

__Return Value__

| Param  |Type  | Description  |
|:---|:---|:---|
|``object``   |_Object_ | Iterator for all the objects in the bucket, the object is of the format listed below:  |

| Param  |Type  | Description  |
|:---|:---|:---|
|``object.bucket_name``  | _string_ | name of the bucket object resides in.|
|``object.object_name``  | _string_ | name of the object.|
|``object.is_dir``       |  _bool_  | `True` if listed object is a dir (prefix) and `False` otherwise.|
|``object.size`` | _int_ | size of the object.|
|``object.etag`` | _string_ | etag of the object.|
|``object.last_modified`` |_datetime.datetime_ | modified time stamp.|

__Example__

```py
# List all object paths in bucket that begin with my-prefixname.
objects = minioClient.list_objects('mybucket', prefix='my-prefixname',
                              recursive=True)
for obj in objects:
    print(obj.bucket_name, obj.object_name.encode('utf-8'), obj.last_modified,
          obj.etag, obj.size, obj.content_type)
```

<a name="list_objects_v2"></a>
### list_objects_v2(bucket_name, prefix=None, recursive=False)
Lists objects in a bucket using the Version 2 API.

__Parameters__

| Param  |Type  | Description  |
|:---|:---|:---|
|``bucket_name`` | _string_ | Name of the bucket.|
|``prefix``| _string_ |The prefix of the objects that should be listed.  Optional, default is None.|
|``recursive``   | _bool_ |``True`` indicates recursive style listing and ``False`` indicates directory style listing delimited by '/'. Optional, default is False.|

__Return Value__

| Param  |Type  | Description  |
|:---|:---|:---|
|``object``   |_Object_ | Iterator for all the objects in the bucket, the object is of the format listed below:  |

| Param  |Type  | Description  |
|:---|:---|:---|
|``object.bucket_name``  | _string_ | name of the bucket object resides in.|
|``object.object_name``  | _string_ | name of the object.|
|``object.is_dir``       |  _bool_  | `True` if listed object is a dir (prefix) and `False` otherwise.|
|``object.size`` | _int_ | size of the object.|
|``object.etag`` | _string_ | etag of the object.|
|``object.last_modified`` |_datetime.datetime_ | modified time stamp.|

__Example__

```py
# List all object paths in bucket that begin with my-prefixname.
objects = minioClient.list_objects_v2('mybucket', prefix='my-prefixname',
                              recursive=True)
for obj in objects:
    print(obj.bucket_name, obj.object_name.encode('utf-8'), obj.last_modified,
          obj.etag, obj.size, obj.content_type)
```

<a name="list_incomplete_uploads"></a>
### list_incomplete_uploads(bucket_name, prefix, recursive=False)
Lists partially uploaded objects in a bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_|Name of the bucket.|
|``prefix``   |_string_ |The prefix of the incomplete objects uploaded should be listed. |
|``recursive`` |_bool_ |``True`` indicates recursive style listing and ``False`` indicates directory style listing delimited by '/'. Optional default is ``False``.   |

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``multipart_obj``   | _Object_  |Iterator of multipart objects of the format described below:|

|Param   |Type   |Description   |
|:---|:---|:---|
|``multipart_obj.object_name``   | _string_  |name of the incomplete object.|
|``multipart_obj.upload_id``   | _string_  |upload ID of the incomplete object.|
|``multipart_obj.size``   | _int_  |size of the incompletely uploaded object.|

__Example__


```py
# List all object paths in bucket that begin with my-prefixname.
uploads = minioClient.list_incomplete_uploads('mybucket',
                                         prefix='my-prefixname',
                                         recursive=True)
for obj in uploads:
    print(obj.bucket_name, obj.object_name, obj.upload_id, obj.size)
```

<a name="get_bucket_policy"></a>
### get_bucket_policy(bucket_name)
Gets current policy of a bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_  |Name of the bucket.|

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``Policy``    |  _string_ | Bucket policy in JSON format.|

__Example__


```py
# Get current policy of all object paths in bucket "mybucket".
policy = minioClient.get_bucket_policy('mybucket')
print(policy)
```

<a name="set_bucket_policy"></a>
### set_bucket_policy(bucket_name, policy)

Set a bucket policy for a specified bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``  | _string_  |Name of the bucket.|
|``Policy``   | _string_ | Bucket policy in JSON format.|


__Example__


```py
# Set bucket policy to read only to all object paths in bucket.
policy_read_only = {"Version":"2012-10-17",
                    "Statement":[
                        {
                        "Sid":"",
                        "Effect":"Allow",
                        "Principal":{"AWS":"*"},
                        "Action":"s3:GetBucketLocation",
                        "Resource":"arn:aws:s3:::mybucket"
                        },
                        {
                        "Sid":"",
                        "Effect":"Allow",
                        "Principal":{"AWS":"*"},
                        "Action":"s3:ListBucket",
                        "Resource":"arn:aws:s3:::mybucket"
                        },
                        {
                        "Sid":"",
                        "Effect":"Allow",
                        "Principal":{"AWS":"*"},
                        "Action":"s3:GetObject",
                        "Resource":"arn:aws:s3:::mybucket/*"
                        }
                    ]}


minioClient.set_bucket_policy('mybucket', policy_read_only)
```

<a name="get_bucket_notification"></a>
### get_bucket_notification(bucket_name)

Fetch the notifications configuration on a bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_  |Name of the bucket.|

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``notification``   | _dict_   | If there is no notification configuration, an empty dictionary is returned. Otherwise it has the same structure as the argument to set_bucket_notification   |

__Example__


```py
# Get the notifications configuration for a bucket.
notification = minioClient.get_bucket_notification('mybucket')
# If no notification is present on the bucket:
# notification == {}
```

<a name="set_bucket_notification"></a>
### set_bucket_notification(bucket_name, notification)

Set notification configuration on a bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_  |Name of the bucket.|
|``notification``  | _dict_    |Non-empty dictionary with the structure specified below.|

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


There is no return value. If there are errors from the target
server/service, a `ResponseError` is thrown. If there are validation
errors, `InvalidArgumentError` or `TypeError` may be thrown. The input
configuration cannot be empty - to delete the notification
configuration on a bucket, use the `remove_all_bucket_notification()`
API.

__Example__


```py
notification = {
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


try:
    minioClient.set_bucket_notification('mybucket', notification)
except ResponseError as err:
    # handle error response from service.
    print(err)
except (ArgumentError, TypeError) as err:
    # should happen only during development. Fix the notification argument
    print(err)
```

<a name="remove_all_bucket_notification"></a>
### remove_all_bucket_notification(bucket_name)

Remove all notifications configured on the bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_  |Name of the bucket.|

There is no returned value. A `ResponseError` exception is thrown if
the operation did not complete successfully.

__Example__


```py
# Remove all the notifications config for a bucket.
minioClient.remove_all_bucket_notification('mybucket')
```

<a name="listen_bucket_notification"></a>
### listen_bucket_notification(bucket_name, prefix, suffix, events)

Listen for notifications on a bucket. Additionally one can provide
filters for prefix, suffix and events. There is no prior set bucket notification
needed to use this API. This is an MinIO extension API where unique identifiers
are registered and unregistered by the server automatically based on incoming
requests.

Yields events as they occur, caller has to iterate to read these events as
they occur.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_  |Bucket name to listen event notifications from.|
|``prefix`` | _string_ | Object key prefix to filter notifications for. |
|``suffix`` | _string_  | Object key suffix to filter notifications for. |
|``events`` | _list_ | Enables notifications for specific event types. |

See [here](https://raw.githubusercontent.com/minio/minio-py/master/examples/listen_notification.py) for a full example.

```py
# Put a file with default content-type.
events = minioClient.listen_bucket_notification('my-bucket', 'my-prefix/',
                                                '.my-suffix',
                                                ['s3:ObjectCreated:*',
                                                 's3:ObjectRemoved:*',
                                                 's3:ObjectAccessed:*'])
for event in events:
    print event
```

## 3. Object operations
<a name="get_object"></a>
### get_object(bucket_name, object_name, request_headers=None)
Downloads an object.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket.   |
|``object_name``   |_string_   |Name of the object.   |
|``request_headers`` |_dict_   |Any additional headers (optional, defaults to None).   |
|``sse`` |_dict_   |Server-Side Encryption headers (optional, defaults to None).   |

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``object``   | _urllib3.response.HTTPResponse_   |Represents http streaming reader.   |

__Example__


```py
# Get a full object.
try:
    data = minioClient.get_object('mybucket', 'myobject')
    with open('my-testfile', 'wb') as file_data:
        for d in data.stream(32*1024):
            file_data.write(d)
except ResponseError as err:
    print(err)
```

<a name="get_partial_object"></a>
### get_partial_object(bucket_name, object_name, offset=0, length=0, request_headers=None)
Downloads the specified range bytes of an object.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_  |Name of the bucket.   |
|``object_name``   |_string_  |Name of the object.   |
|``offset``   |_int_ |``offset`` of the object from where the stream will start.   |
|``length``   |_int_ |``length`` of the object that will be read in the stream (optional, if not specified we read the rest of the file from the offset).   |
|``request_headers`` |_dict_   |Any additional headers (optional, defaults to None).   |
|``sse`` |_dict_   |Server-Side Encryption headers (optional, defaults to None).   |

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``object``   | _urllib3.response.HTTPResponse_   |Represents http streaming reader.   |

__Example__

```py
# Offset the download by 2 bytes and retrieve a total of 4 bytes.
try:
    data = minioClient.get_partial_object('mybucket', 'myobject', 2, 4)
    with open('my-testfile', 'wb') as file_data:
        for d in data:
            file_data.write(d)
except ResponseError as err:
    print(err)
```

<a name="select_object_content"></a>
### select_object_content(self, bucket_name, object_name, options)
Select object content filters the contents of object based on a simple structured query language (SQL).

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket.   |
|``object_name``   |_string_   |Name of the object.   |
|``options`` | _SelectObjectReader_ | Query Options   |


__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``obj``| _SelectObjectReader_  |Select_object_reader object.  |



__Example__


```py
client = Minio('s3.amazonaws.com',
               access_key='YOUR-ACCESSKEY',
               secret_key='YOUR-SECRETKEY')

options = SelectObjectOptions(
    expression=" select * from s3object",
    input_serialization=InputSerialization(
        compression_type="NONE",
        csv=CSVInput(FileHeaderInfo="USE",
                     RecordDelimiter="\n",
                     FieldDelimiter=",",
                     QuoteCharacter='"',
                     QuoteEscapeCharacter='"',
                     Comments="#",
                     AllowQuotedRecordDelimiter="FALSE",
                     ),
        ),

    output_serialization=OutputSerialization(
        csv=CSVOutput(QuoteFields="ASNEEDED",
                      RecordDelimiter="\n",
                      FieldDelimiter=",",
                      QuoteCharacter='"',
                      QuoteEscapeCharacter='"',)
                      ),
    request_progress=RequestProgress(
        enabled="FLASE"
        )
    )

try:
    data = client.select_object_content('my-bucket', 'my-object', options)

    # Get the records
    with open('my-record-file', 'w') as record_data:
        for d in data.stream(10*1024):
            record_data.write(d)

    # Get the stats
    print(data.stats())

except CRCValidationError as err:
    print(err)
except ResponseError as err:
    print(err)

```

<a name="fget_object"></a>
### fget_object(bucket_name, object_name, file_path, request_headers=None)
Downloads and saves the object as a file in the local filesystem.

__Parameters__


|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket.   |
|``object_name``   |_string_    |Name of the object.   |
|``file_path``   |_dict_ | Path on the local filesystem to which the object data will be written. |
|``request_headers`` |_dict_   |Any additional headers (optional, defaults to None).   |
|``sse`` |_dict_   |Server-Side Encryption headers (optional, defaults to None).   |

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``obj``|_Object_  |object stat info for format described below:  |

|Param   |Type   |Description   |
|:---|:---|:---|
|``obj.size``|_int_  |size of the object. |
|``obj.etag``|_string_|etag of the object.|
|``obj.content_type``|_string_  | Content-Type of the object.|
|``obj.last_modified``|_time.time_  |modified time stamp.|
|``obj.metadata`` |_dict_ | Contains any additional metadata on the object. |

__Example__

```py
# Get a full object and prints the original object stat information.
try:
    print(minioClient.fget_object('mybucket', 'myobject', '/tmp/myobject'))
except ResponseError as err:
    print(err)
```

<a name="copy_object"></a>
### copy_object(bucket_name, object_name, object_source, copy_conditions=None, metadata=None)
 Copy a source object on object storage server to a new object.

 NOTE: Maximum object size supported by this API is 5GB.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket for new object.   |
|``object_name``   |_string_    |Name of the new object.   |
|``object_source``   |_string_   |Name of the object to be copied. |
|``copy_conditions`` |_CopyConditions_ | Collection of conditions to be satisfied for the request (optional, defaults to 'None'). |
|``source_sse`` |_dict_   |Server-Side Encryption headers for source object (optional, defaults to None).   |
|``sse`` |_dict_   |Server-Side Encryption headers for destination object (optional, defaults to None).   |
|``metadata`` |_dict_   |User defined metadata to be copied with the destination object (optional, defaults to None).   |


__Example__

All following conditions are allowed and can be combined together.

```py
import time
from datetime import datetime
from minio import CopyConditions

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

try:
    copy_result = minioClient.copy_object("mybucket", "myobject",
                                          "/my-sourcebucketname/my-sourceobjectname",
                                          copy_conditions,metadata=metadata)
    print(copy_result)
except ResponseError as err:
    print(err)
```

<a name="put_object"></a>
### put_object(bucket_name, object_name, data, length, content_type='application/octet-stream', metadata=None,  progress=None, part_size=5*1024*1024)
Add a new object to the object storage server. If provided metadata key is not one of the valid/supported metadata names, the metadata information is saved with prefix `X-Amz-Meta-` prepended to the original metadata key name.

NOTE: Maximum object size supported by this API is 5TiB.

__Parameters__

| Param            | Type                    | Description                                                                     |
|:-----------------|:------------------------|:--------------------------------------------------------------------------------|
| ``bucket_name``  | _string_                | Name of the bucket.                                                             |
| ``object_name``  | _string_                | Name of the object.                                                             |
| ``data``         | _io.RawIOBase_          | Any python object implementing io.RawIOBase.                                    |
| ``length``       | _int_                   | Total length of object.                                                         |
| ``content_type`` | _string_                | Content type of the object. (optional, defaults to 'application/octet-stream'). |
| ``metadata``     | _dict_                  | Any additional metadata. (optional, defaults to None).                          |
| ``sse``          | _dict_                  | Server-Side Encryption headers (optional, defaults to None).                    |
| ``progress``     | _subclass_of_threading_ | A progress object (optional, defaults to None).                                 |
| ``part_size``    | _int_                   | Multipart part size.                                                            |

__Return Value__

| Param    | Type     | Description                         |
|:---------|:---------|:------------------------------------|
| ``etag`` | _string_ | Object etag computed by the server. |

__Example__

The maximum size of a single object is limited to 5TB. put_object transparently uploads objects larger than 5MiB in multiple parts. This allows failed uploads to resume safely by only uploading the missing parts. Uploaded data is carefully verified using MD5SUM.

```py
import os
# Put a file with default content-type, upon success prints the etag identifier computed by server.
try:
    with open('my-testfile', 'rb') as file_data:
        file_stat = os.stat('my-testfile')
        print(minioClient.put_object('mybucket', 'myobject',
                               file_data, file_stat.st_size))
except ResponseError as err:
    print(err)

# Put a file with 'application/csv'.
try:
    with open('my-testfile.csv', 'rb') as file_data:
        file_stat = os.stat('my-testfile.csv')
        minioClient.put_object('mybucket', 'myobject.csv', file_data,
                    file_stat.st_size, content_type='application/csv')

except ResponseError as err:
    print(err)
```

<a name="fput_object"></a>
### fput_object(bucket_name, object_name, file_path, content_type='application/octet-stream', metadata=None, progress=None, part_size=5*1024*1024)
Uploads contents from a file, `file_path`, to `object_name`. If provided metadata key is not one of the valid/supported metadata names, the metadata information is saved with prefix `X-Amz-Meta-` prepended to the original metadata key name.

__Parameters__

| Param            | Type                    | Description                                                                    |
|:-----------------|:------------------------|:-------------------------------------------------------------------------------|
| ``bucket_name``  | _string_                | Name of the bucket.                                                            |
| ``object_name``  | _string_                | Name of the object.                                                            |
| ``file_path``    | _string_                | Path on the local filesystem from which object data will be read.              |
| ``content_type`` | _string_                | Content type of the object (optional, defaults to 'application/octet-stream'). |
| ``metadata``     | _dict_                  | Any additional metadata (optional, defaults to None).                          |
| ``sse``          | _dict_                  | Server-Side Encryption headers (optional, defaults to None).                   |
| ``progress``     | _subclass_of_threading_ | A progress object (optional, defaults to None).                                |
| ``part_size``    | _int_                   | Multipart part size.                                                           |

__Return Value__

| Param    | Type     | Description                         |
|:---------|:---------|:------------------------------------|
| ``etag`` | _string_ | Object etag computed by the server. |

__Example__

The maximum size of a single object is limited to 5TB. fput_object transparently uploads objects larger than 5MiB in multiple parts. This allows failed uploads to resume safely by only uploading the missing parts. Uploaded data is carefully verified using MD5SUM.

```py
# Put an object 'myobject' with contents from '/tmp/otherobject', upon success prints the etag identifier computed by server.
try:
    print(minioClient.fput_object('mybucket', 'myobject', '/tmp/otherobject'))
except ResponseError as err:
    print(err)

# Put on object 'myobject.csv' with contents from
# '/tmp/otherobject.csv' as 'application/csv'.
try:
    print(minioClient.fput_object('mybucket', 'myobject.csv',
                             '/tmp/otherobject.csv',
                             content_type='application/csv'))
except ResponseError as err:
    print(err)
```

<a name="stat_object"></a>
### stat_object(bucket_name, object_name)
Gets metadata of an object. If provided metadata key is not one of the valid/supported metadata names when the object was put/fput, the metadata information is saved with prefix `X-Amz-Meta-` prepended to the original metadata key name. So, the metadata returned by stat_object api will be presented with the original metadata key name prepended with `X-Amz-Meta-`.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_  |Name of the bucket.   |
|``object_name``   |_string_  |Name of the object.   |
|``sse`` |_dict_   |Server-Side Encryption headers (optional, defaults to None).   |

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``obj``|_Object_  |object stat info for format described below:  |

|Param   |Type   |Description   |
|:---|:---|:---|
|``obj.size``|_int_  |size of the object. |
|``obj.etag``|_string_|etag of the object.|
|``obj.content_type``|_string_  | Content-Type of the object.|
|``obj.last_modified``|_time.time_  | modified time in UTC.|
|``obj.metadata`` |_dict_ | Contains any additional metadata on the object. |


__Example__


```py
# Fetch stats on your object.
try:
    print(minioClient.stat_object('mybucket', 'myobject'))
except ResponseError as err:
    print(err)
```

<a name="remove_object"></a>
### remove_object(bucket_name, object_name)
Removes an object.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket.   |
|``object_name``   |_string_    |Name of the object.   |

__Example__


```py
# Remove an object.
try:
    minioClient.remove_object('mybucket', 'myobject')
except ResponseError as err:
    print(err)
```

<a name="remove_objects"></a>
### remove_objects(bucket_name, objects_iter)
Removes multiple objects in a bucket.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   | _string_  | Name of the bucket.   |
|``objects_iter``   | _list_ , _tuple_ or _iterator_ | List-like value containing object-name strings to delete.   |

__Return Value__

|Param   |Type   |Description   |
|:---|:---|:---|
|``delete_error_iterator`` | _iterator_ of _MultiDeleteError_ instances | Lazy iterator of delete errors described below. |

_NOTE:_

1. The iterator returned above must be evaluated (for e.g. using
a loop), as the function is lazy and will not evaluate by default.

2. The iterator will contain items only if there are errors when the
service performs a delete operation on it. Each item contains error
information for an object that had a delete error.

Each delete error produced by the iterator has the following
structure:

|Param |Type |Description |
|:---|:---|:---|
|``MultiDeleteError.object_name`` | _string_ | Object name that had a delete error. |
|``MultiDeleteError.error_code`` | _string_ | Error code. |
|``MultiDeleteError.error_message`` | _string_ | Error message. |

__Example__


```py
# Remove multiple objects in a single library call.
try:
    objects_to_delete = ['myobject-1', 'myobject-2', 'myobject-3']
    # force evaluation of the remove_objects() call by iterating over
    # the returned value.
    for del_err in minioClient.remove_objects('mybucket', objects_to_delete):
        print("Deletion Error: {}".format(del_err))
except ResponseError as err:
    print(err)
```

<a name="remove_incomplete_upload"></a>
### remove_incomplete_upload(bucket_name, object_name)
Removes a partially uploaded object.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket.   |
|``object_name``   |_string_   |Name of the object.   |

__Example__


```py
# Remove an partially uploaded object.
try:
    minioClient.remove_incomplete_upload('mybucket', 'myobject')
except ResponseError as err:
    print(err)
```

## 4. Presigned operations

<a name="presigned_get_object"></a>
### presigned_get_object(bucket_name, object_name, expires=timedelta(days=7))
Generates a presigned URL for HTTP GET operations. Browsers/Mobile clients may point to this URL to directly download objects even if the bucket is private. This presigned URL can have an associated expiration time in seconds after which it is no longer operational. The default expiry is set to 7 days.

__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_   |Name of the bucket.   |
|``object_name``   |_string_    |Name of the object.   |
|``expires``   | _datetime.timedelta_    |Expires in timedelta. Default expiry is set to 7 days.    |
|``response_headers``   | _dictionary_    |Additional headers to include (e.g. `response-content-type` or `response-content-disposition`)     |
|``request_date``   | _datetime.datetime_    |Optional datetime to specify a different request date. Expiry is relative to the request date. Default is current date.     |

__Example__


```py
from datetime import timedelta

# presigned get object URL for object name, expires in 2 days.
try:
    print(minioClient.presigned_get_object('mybucket', 'myobject', expires=timedelta(days=2)))
# Response error is still possible since internally presigned does get bucket location.
except ResponseError as err:
    print(err)
```

<a name="presigned_put_object"></a>
### presigned_put_object(bucket_name, object_name, expires=timedelta(days=7))
Generates a presigned URL for HTTP PUT operations. Browsers/Mobile clients may point to this URL to upload objects directly to a bucket even if it is private. This presigned URL can have an associated expiration time in seconds after which it is no longer operational. The default expiry is set to 7 days.

NOTE: you can upload to S3 only with specified object name.


__Parameters__

|Param   |Type   |Description   |
|:---|:---|:---|
|``bucket_name``   |_string_  |Name of the bucket.   |
|``object_name``   |_string_    |Name of the object.   |
|``expiry``   | _datetime.datetime_    |Expiry in seconds. Default expiry is set to 7 days.    |

__Example__

```py
from datetime import timedelta

# presigned Put object URL for an object name, expires in 3 days.
try:
    print(minioClient.presigned_put_object('mybucket',
                                      'myobject',
                                      expires=timedelta(days=3)))
# Response error is still possible since internally presigned does get
# bucket location.
except ResponseError as err:
    print(err)
```

<a name="presigned_post_policy"></a>
### presigned_post_policy(PostPolicy)
Allows setting policy conditions to a presigned URL for POST operations. Policies such as bucket name to receive object uploads, key name prefixes, expiry policy may be set.

Create policy:

```py
from datetime import datetime, timedelta

from minio import PostPolicy
post_policy = PostPolicy()

# Apply upload policy restrictions:

# set bucket name location for uploads.
post_policy.set_bucket_name('mybucket')
# set key prefix for all incoming uploads.
post_policy.set_key_startswith('myobject')
# set content length for incoming uploads.
post_policy.set_content_length_range(10, 1024)
# set content-type to allow only text
post_policy.set_content_type('text/plain')

# set expiry 10 days into future.
expires_date = datetime.utcnow()+timedelta(days=10)
post_policy.set_expires(expires_date)
```
Get the POST form key/value object:

```py
try:
    signed_form_data = minioClient.presigned_post_policy(post_policy)
except ResponseError as err:
    print(err)
```

POST your content from the command line using `curl`:


```py
curl_str = 'curl -X POST {0}'.format(signed_form_data[0])
curl_cmd = [curl_str]
for field in signed_form_data[1]:
    curl_cmd.append('-F {0}={1}'.format(field, signed_form_data[1][field]))

# print curl command to upload files.
curl_cmd.append('-F file=@<FILE>')
print(' '.join(curl_cmd))
```

## 5. Explore Further

- [MinIO Golang Client SDK Quickstart Guide](https://docs.min.io/docs/golang-client-quickstart-guide)
- [MinIO Java Client SDK Quickstart Guide](https://docs.min.io/docs/java-client-quickstart-guide)
- [MinIO JavaScript Client SDK Quickstart Guide](https://docs.min.io/docs/javascript-client-quickstart-guide)
