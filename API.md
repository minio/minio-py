# Python Client API Reference

Initialize Minio Client object.

``1. Minio``
```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio('play.minio.io:9000',
                  access_key='Q3AM3UQ867SPQQA43P2F',
                  secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG',
                  secure=True)
```

``2. AWS S3``
```py
from minio import Minio
from minio.error import ResponseError

s3Client = Minio('s3.amazonaws.com',
                 access_key='YOUR-ACCESSKEYID',
                 secret_key='YOUR-SECRETACCESSKEY',
                 secure=True)
```



|Bucket operations | Object operations| Presigned operations |
|:---|:---|:---|
| [`make_bucket`](#make_bucket)  | [`get_object`](#get_object)  | [`presigned_get_object`](#presigned_get_object)  |
|[`list_buckets`](#list_buckets)   | [`put_object`](#put_object)  | [`presigned_put_object`](#presigned_put_object)  |
| [`bucket_exists`](#bucket_exists)  |[`stat_object`](#stat_object)   |[`presigned_post_policy`](#presigned_post_policy)   |
|[`remove_bucket`](#remove_bucket)   | [`remove_object`](#remove_object)  |   |
| [`list_objects`](#list_objects)  | [`remove_incomplete_upload`](#remove_incomplete_upload)  |   | 
|[`list_incomplete_uploads`](#list_incomplete_uploads)   |  [`fput_object`](#fput_object) |   |
|  |[`fget_object`](#fget_object)  |  | 
|  |[`get_partial_object`](#get_partial_object)  |  | 

## 1. Constructor

<a name="Minio">
#### Minio(endpoint, access_key=None, secret_key=None, secure=True)

|   |
|---|
| `Minio(endpoint, access_key=None, secret_key=None, secure=True)`  |
| Initializes a new client object.  |

__Parameters__


| :Param  | :Type | :Description  |
|---|---|---|
| `endpoint`  | _string_  | S3 object storage endpoint.  |
| `access_key`  | _string_  | Access key for the object storage endpoint. (Optional if you need anonymous access).  |
|  `secret_key` | _string_  |  Secret key for the object storage endpoint. (Optional if you need anonymous access). |
| `secure`  |_bool_   | Set this value to `True` to enable secure (HTTPS) access. (Optional defaults to `True`).  |

__Example__

``1. Minio``
```py
from minio import Minio
from minio.error import ResponseError

minioClient = Minio('play.minio.io:9000',
                    access_key='Q3AM3UQ867SPQQA43P2F',
                    secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
```

``2. AWS S3``
```py
from minio import Minio
from minio.error import ResponseError

s3Client = Minio('s3.amazonaws.com',
                 access_key='ACCESS_KEY',
                 secret_key='SECRET_KEY')
```

## 2. Bucket operations

<a name="make_bucket">
#### make_bucket(bucket_name, location='us-east-1')
Creates a new bucket.

__Parameters__

<table>
    <thead>
        <tr>
            <th>Param</th>
            <th>Type</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
           bucket_name
            </td>
            <td> string</td>
            <td> Name of the bucket.</td>
            </tr>
            <tr>
            <td>location</td>
            <td>string</td>
            <td>Default value is us-east-1<br/>
Location valid values are us-west-1, us-west-2, eu-west-1, eu-central-1, ap-southeast-1, ap-northeast-1, ap-southeast-2, sa-east-1(defaults to us-east-1, optional).</td>
            </tr>
               </tbody>
</table>


__Example__
```py
try:
    minioClient.make_bucket("mybucket", location="us-east-1")
except ResponseError as err:
    print(err)
```

<a name="list_buckets">
#### list_buckets()
Lists all buckets.

__Parameters__

|Return   |Type   |Description   |
|---|---|---|
|``bucketList``   |*function*   |List of all buckets. |
|``bucket_name``   |*string*   |Bucket name. |
|``bucket.creation_date`` |*time*   |Time: date when bucket was created. |

__Example__
```py
buckets = minioClient.list_buckets()
for bucket in buckets:
    print(bucket.name, bucket.creation_date)
```

<a name="bucket_exists">
#### bucket_exists(bucket_name)
Checks if a bucket exists.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket. |

__Example__

```py
try:
    print(minioClient.bucket_exists("mybucket"))
except ResponseError as err:
    print(err)
```

<a name="remove_bucket">
#### remove_bucket(bucket_name)
Removes a bucket.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket. |

__Example__
```py
try:
    minioClient.remove_bucket("mybucket")
except ResponseError as err:
    print(err)
```

<a name="list_objects">
#### list_objects(bucket_name, prefix, recursive=False)
Lists objects in a bucket.

__Parameters__

| Param  |Type  | Description  |
|---|---|---|
|``bucket_name``   |*string*   | Name of the bucket.  |
|``objectPrefix``   | *string*   |The prefix of the objects that should be listed. |
|``recursive``   | *bool*   |``True`` indicates recursive style listing and ``False`` indicates directory style listing delimited by '/'. Optional default is ``False``.   |

__Return Value__

<table>
    <thead>
        <tr>
            <th>Param</th>
            <th>Type</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
           object
            </td>
            <td> Object</td>
            <td> Iterator for all the objects in the bucket, the object is of the format:
            <ul>
            <li>object.object_name string: name of the object. </li>
            <li>object.size int: size of the object.</li>
            <li>object.etag string: etag of the object. </li>
            <li>object.last_modified datetime.datetime: modified time stamp. </li>
            </ul>
            </td>
            </tr>
               </tbody>
</table>

__Example__

```py
# List all object paths in bucket that begin with my-prefixname.
objects = minioClient.list_objects('mybucket', prefix='my-prefixname',
                              recursive=True)
for obj in objects:
    print(obj.bucket_name, obj.object_name.encode('utf-8'), obj.last_modified,
          obj.etag, obj.size, obj.content_type)
```

<a name="list_incomplete_uploads">
#### list_incomplete_uploads(bucket_name, prefix, recursive=False)
Lists partially uploaded objects in a bucket.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucketname``   | *string*  |Name of the bucket.|
|``prefix``   |*string*    |The prefix of the incomplete objects uploaded should be listed. |
|``recursive`` |*bool*   |``True`` indicates recursive style listing and ``False`` indicates directory style listing delimited by '/'. Optional default is ``False``.   |

__Return Value__

<table>
    <thead>
        <tr>
            <th>Param</th>
            <th>Type</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
           multipart_obj
            </td>
            <td> Object</td>
            <td> Iterator of multipart objects of the format:
            <ul>
            <li>multipart_obj.object_name string: name of the incomplete object.</li>
            <li>multipart_obj.upload_id string: upload ID of the incomplete object.</li>
            <li>multipart_obj.size int: size of the incompletely uploaded object. </li>
            </ul>
            </td>
            </tr>
               </tbody>
</table>

__Example__

```py
# List all object paths in bucket that begin with my-prefixname.
uploads = minioClient.list_incomplete_uploads('mybucket',
                                         prefix='my-prefixname',
                                         recursive=True)
for obj in uploads:
    print(obj.bucket_name, obj.object_name, obj.upload_id, obj.size)
```

## 3. Object operations
<a name="get_object">
#### get_object(bucket_name, object_name)
Downloads an object.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*   |Name of the object.   |
__Return Value__

|Param   |Type   |Description   |
|---|---|---|
|``object``   | *io.IOBase*   |Represents object reader.   |

__Example__

```py
# Get a full object.
try:
    data = minioClient.get_object('mybucket', 'myobject')
    with open('my-testfile', 'wb') as file_data:
        for d in data:
            file_data.write(d)
except ResponseError as err:
    print(err)
```

<a name="get_partial_object">
#### get_partial_object(bucket_name, object_name, offset=0, length=0)
Downloads the specified range bytes of an object.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |
|``offset``   |*int*   |``offset`` of the object from where the stream will start.   |
|``length``   |*int*    |``length`` of the object that will be read in the stream (optional, if not specified we read the rest of the file from the offset).   |

__Return Value__

|Param   |Type   |Description   |
|---|---|---|
|``object``   | *io.IOBase*   |Represents object reader.   |

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

<a name="fget_object">
#### fget_object(bucket_name, object_name, file_path)
Downloads and saves the object as a file in the local filesystem.

__Parameters__


|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |
|``file_path``   |*string* | Path on the local filesystem to which the object data will be written. |

__Example__

```py
# Get a full object.
try:
    minioClient.fget_object('mybucket', 'myobject', '/tmp/myobject')
except ResponseError as err:
    print(err)
```

<a name="put_object">
#### put_object(bucket_name, object_name, data, length, content_type)
Uploads an object.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |
|``data``   |*io.IOBase*   |Any python object implementing io.IOBase. |
|``length``   |*int*   |Total length of object.   |
|``content_type``   |*string* | Content type of the object. (optional, defaults to '``application/octet-stream``').   |

__Example__

The maximum size of a single object is limited to 5TB. put_object transparently uploads objects larger than 5MiB in multiple parts. This allows failed uploads to resume safely by only uploading the missing parts. Uploaded data is carefully verified using MD5SUM signatures.

```py
import os
# Put a file with default content-type.
try:
    file_stat = os.stat('my-testfile')
    file_data = open('my-testfile', 'rb')
    minioClient.put_object('mybucket', 'myobject', file_data, file_stat.st_size)
except ResponseError as err:
    print(err)

# Put a file with 'application/csv'.
try:
    file_stat = os.stat('my-testfile.csv')
    file_data = open('my-testfile.csv', 'rb')
    minioClient.put_object('mybucket', 'myobject.csv', file_data,
                      file_stat.st_size, content_type='application/csv')
except ResponseError as err:
    print(err)
```

<a name="fput_object">
#### fput_object(bucket_name, object_name, file_path, content_type)
Uploads contents from a file to objectName. 

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |
|``file_path``   |*string*   |Path on the local filesystem to which the object data will be written. |
|``content_type``   |*string* | Content type of the object. (optional, defaults to '``application/octet-stream``').   |

__Example__

The maximum size of a single object is limited to 5TB. fput_object transparently uploads objects larger than 5MiB in multiple parts. This allows failed uploads to resume safely by only uploading the missing parts. Uploaded data is carefully verified using MD5SUM signatures.

```py
# Put an object 'myobject' with contents from '/tmp/otherobject'.
try:
    minioClient.fput_object('mybucket', 'myobject', '/tmp/otherobject')
except ResponseError as err:
    print(err)

# Put on object 'myobject.csv' with contents from
# '/tmp/otherobject.csv' as 'application/csv'.
try:
    minioClient.fput_object('mybucket', 'myobject.csv',
                       '/tmp/otherobject.csv', content_type='application/csv')
except ResponseError as err:
    print(err)

```

<a name="stat_object">
#### stat_object(bucket_name, object_name)
Gets metadata of an object.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |

__Return Value__

<table>
    <thead>
        <tr>
            <th>Param</th>
            <th>Type</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
           obj
            </td>
            <td> Object</td>
            <td> object stat info for following format:
            <ul>
            <li>obj.size int: size of the object.</li>
            <li>obj.etag string: etag of the object.</li>
            <li>obj.content_type string: Content-Type of the object.</li>
            <li>obj.last_modified time.time: modified time stamp.</li>
            </ul>
            </td>
            </tr>
               </tbody>
</table>

__Example__
```py
# Fetch stats on your object.
try:
    print(minioClient.stat_object('mybucket', 'myobject'))
except ResponseError as err:
    print(err)
```

<a name="remove_object">
#### remove_object(bucket_name, object_name)
Removes an object.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |

__Example__

```py
# Remove an object.
try:
    minioClient.remove_object('mybucket', 'myobject')
except ResponseError as err:
    print(err)
```


<a name="remove_incomplete_upload">
#### remove_incomplete_upload(bucket_name, object_name)
Removes a partially uploaded object.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |

__Example__

```py
# Remove an partially uploaded object.
try:
    minioClient.remove_incomplete_upload('mybucket', 'myobject')
except ResponseError as err:
    print(err)
```
## 4. Presigned operations

<a name="presigned_get_object">
#### presigned_get_object(bucket_name, object_name, expiry=timedelta(days=7))
Generates a presigned URL for HTTP GET operations. Browsers/Mobile clients may point to this URL to directly download objects even if the bucket is private. This presigned URL can have an associated expiration time in seconds after which it is no longer operational. The default expiry is set to 7 days.

__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |
|``expiry``   | *datetime.datetime*    |Expiry in seconds. Default expiry is set to 7 days.    |

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


<a name="presigned_put_object">
#### presigned_put_object(bucket_name, object_name, expires=timedelta(days=7))
Generates a presigned URL for HTTP PUT operations. Browsers/Mobile clients may point to this URL to upload objects directly to a bucket even if it is private. This presigned URL can have an associated expiration time in seconds after which it is no longer operational. The default expiry is set to 7 days.

NOTE: you can upload to S3 only with specified object name.


__Parameters__

|Param   |Type   |Description   |
|---|---|---|
|``bucket_name``   |*string*   |Name of the bucket.   |
|``object_name``   |*string*    |Name of the object.   |
|``expiry``   | *datetime.datetime*    |Expiry in seconds. Default expiry is set to 7 days.    |

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

<a name="presigned_post_policy">
#### presigned_post_policy
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
 
- [Minio Golang Client SDK Quickstart Guide](/docs/golang-client-quickstart-guide) 
- [Minio Java Client SDK Quickstart Guide](/docs/java-client-quickstart-guide) 
- [Minio JavaScript Client SDK Quickstart Guide](/docs/javascript-client-quickstart-guide)












