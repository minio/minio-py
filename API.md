## API Documentation

### Minio client object creation
Minio client object is created using minio-py:
```py
from minio import Minio
from minio.error import ResponseError

s3client = Minio('s3.amazonaws.com',
                 access_key='YOUR-ACCESSKEYID',
                 secret_key='YOUR-SECRETACCESSKEY')
```

s3client can be used to perform operations on S3 storage. APIs are described below.

### Bucket operations
* [`make_bucket`](#make_bucket)
* [`list_buckets`](#list_buckets)
* [`bucket_exists`](#bucket_exist)
* [`remove_bucket`](#remove_bucket)
* [`get_bucket_acl`](#get_bucket_acl)
* [`set_bucket_acl`](#set_bucket_acl)
* [`list_objects`](#list_objects)
* [`list_incomplete_uploads`](#list_incomplete_uploads)

### Object operations

* [`get_object`](#get_object)
* [`put_object`](#put_object)
* [`stat_object`](#stat_object)
* [`remove_object`](#remove_object)
* [`remove_incomplete_upload`](#remove_incomplete_upload)

### File operations.
* [`fput_object`](#fput_object)
* [`fget_object`](#fget_object)

### Presigned operations

* [`presigned_get_object`](#presigned_get_object)
* [`presigned_put_object`](#presigned_put_object)
* [`presigned_post_policy`](#presigned_post_policy)

### Bucket operations
---------------------------------------
<a name="make_bucket">
#### make_bucket(bucket_name, location, acl)
Create a new bucket.

__Arguments__
* `bucket_name` _string_ - Name of the bucket.
* `location` _string_ - region valid values are _us-west-1_, _us-west-2_,  _eu-west-1_, _eu-central-1_, _ap-southeast-1_, _ap-northeast-1_, _ap-southeast-2_, _sa-east-1_(defaults to _us-east-1_, optional)
* `acl`   _string_ - acl  _Acl.public_read_write()_, _Acl.public_read()_, _Acl.authenticated_read()_, _Acl.private()_ (defaults to _Acl.private()_, optional)

__Example__
```py
from minio import Acl

try:
    s3client.make_bucket("mybucket", location="us-west-1", acl=Acl.public_read_write())
except ResponseError as err:
    print(err)
```
---------------------------------------
<a name="list_buckets">
#### list_buckets()
List all buckets.

`bucketList` lists bucket with the format:
* `bucket.name` _string_: bucket name
* `bucket.creation_date` time.Time : date when bucket was created

__Example__
```py
buckets = s3client.list_buckets()
for bucket in buckets:
    print(bucket.name, bucket.creation_date)
```
---------------------------------------
<a name="bucket_exists">
#### bucket_exists(bucket_name)
Check if bucket exists.

__Arguments__
* `bucket_name` _string_ : name of the bucket

__Example__
```py
try:
    print(s3client.bucket_exists("mybucket"))
except ResponseError as err:
    print(err)
```
---------------------------------------
<a name="remove_bucket">
#### remove_bucket(bucket_name)
Remove a bucket.

__Arguments__
* `bucket_name` _string_ : name of the bucket

__Example__
```py
try:
    s3client.remove_bucket("mybucket")
except ResponseError as err:
    print(err)
```
---------------------------------------
<a name="get_bucket_acl">
#### get_bucket_acl(bucket_name)
Get access permissions.

__Arguments__
* `bucket_name` _string_ : name of the bucket

__Example__
```py
try:
    print(client.get_bucket_acl('my-bucketname'))
except ResponseError as err:
    print(err)
```
---------------------------------------
<a name="set_bucket_acl">
#### set_bucket_acl(bucketname, acl)
Set access permissions.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `acl` _string_: acl can be _private_, _public-read_, _public-read-write_, _authenticated-read_

__Example__
```py
from minio import Acl

# Set bucket name to private.
try:
    client.set_bucket_acl('my-bucketname', Acl.private())
except ResponseError as err:
    print(err)
```

---------------------------------------
<a name="list_objects">
#### list_objects(bucket_name, prefix, recursive=False)
List objects in a bucket.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `objectPrefix` _string_: the prefix of the objects that should be listed
* `recursive` _bool_: `true` indicates recursive style listing and `false` indicates directory style listing delimited by '/'

__Return Value__
 ` object` _Object_: Iterator for all the objects in the bucket, the object is of the format:
  * `object.object_name` _string_: name of the object
  * `object.size` _int_: size of the object
  * `object.etag` _string_: etag of the object
  * `object.last_modified` _datetime.datetime_: modified time stamp

__Example__
```py
# List all object paths in bucket that begin with my-prefixname.
objects = client.list_objects('my-bucketname', prefix='my-prefixname',
                              recursive=True)
for obj in objects:
    print(obj.bucket_name, obj.object_name.encode('utf-8'), obj.last_modified,
          obj.etag, obj.size, obj.content_type)

```

---------------------------------------
<a name="list_incomplete_uploads">
#### list_incomplete_uploads(bucket_name, prefix, recursive)
List partially uploaded objects in a bucket.

__Arguments__
* `bucketname` _string_: name of the bucket
* `prefix` _string_: prefix of the object names that are partially uploaded
* `recursive` bool: directory style listing when false, recursive listing when true

__Return Value__
* `multipart_obj` _IncompleteUpload_ : Iterator of multipart objects of the format:
  * `multipart_obj.object_name` _string_: name of the incomplete object
  * `multipart_obj.upload_id` _string_: upload ID of the incomplete object
  * `multipart_obj.size` _int_: size of the incompletely uploaded object

__Example__
```py
# List all object paths in bucket that begin with my-prefixname.
uploads = client.list_incomplete_uploads('my-bucketname',
                                         prefix='my-prefixname',
                                         recursive=True)
for obj in uploads:
    print(obj.bucket_name, obj.object_name, obj.upload_id, obj.size)
```

---------------------------------------
### Object operations
<a name="get_object">
#### get_object(bucket_name, object_name)
Download an object.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object

__Return Value__
* `object` _io.IOBase_ : _io.IOBase_ represents object reader.

__Example__
```py
# Get a full object
try:
    data = client.get_object('my-bucketname', 'my-objectname')
    with open('my-testfile', 'wb') as file_data:
        for d in data:
            file_data.write(d)
except ResponseError as err:
    print(err)
```

---------------------------------------
<a name="get_partial_object">
#### get_partial_object(bucket_name, object_name, offset, length)
Download an object.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object
* `offset` _int_: offset of the object from where the stream will start
* `length` _int_ : length of the object that will be read in the stream (optional, if not specified we read the rest of the file from the offset)

__Return Value__
* `object` _io.IOBase_ : _io.IOBase_ represents object reader.

__Example__
```py
# Offset the download by 2 bytes and retrieve a total of 4 bytes.
try:
    data = client.get_partial_object('my-bucketname', 'my-objectname', 2, 4)
    with open('my-testfile', 'wb') as file_data:
        for d in data:
            file_data.write(d)
except ResponseError as err:
    print(err)
```
---------------------------------------
---------------------------------------
<a name="fget_object">
#### fget_object(bucket_name, object_name, filePath)
Callback is called with `error` in case of error or `null` in case of success

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object
* `filePath` _string_: path to which the object data will be written to

__Example__
```py
# Get a full object
try:
    client.fget_object('my-bucketname', 'my-objectname', 'filepath')
except ResponseError as err:
    print(err)
```
---------------------------------------
<a name="put_object">
#### put_object(bucket_name, object_name, data, length, content_type)
Upload an object.

Uploading a stream
__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object
* `data` _io.IOBase_: Any python object implementing io.IOBase
* `length` _int_ : total length of object
* `content_type` _string_: content type of the object. (optional, defaults to _'application/octet-stream'_)

__Example__
```py
# Put a file with default content-type.
try:
    file_stat = os.stat('my-testfile')
    file_data = open('my-testfile', 'rb')
    client.put_object('my-bucketname', 'my-objectname', file_data, file_stat.st_size)
except ResponseError as err:
    print(err)

# Put a file with 'application/csv'
try:
    file_stat = os.stat('my-testfile.csv')
    file_data = open('my-testfile.csv', 'rb')
    client.put_object('my-bucketname', 'my-objectname', file_data,
                      file_stat.st_size, content_type='application/csv')
except ResponseError as err:
    print(err)
```


---------------------------------------
<a name="fput_object">
#### fput_object(bucket_name, object_name, file_path, content_type)
Uploads the object using contents from a file

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object
* `file_path` _string_: file path of the file to be uploaded
* `content_type` _string_: content type of the object (optional, defaults to _'application/octet-stream'_)

__Example__
```py
# Put an object 'my-objectname' with contents from 'my-filepath'
try:
    client.fput_object('my-bucketname', 'my-objectname', 'my-filepath')
except ResponseError as err:
    print(err)

# Put on object 'my-objectname-csv' with contents from
# 'my-filepath.csv' as 'application/csv'.
try:
    client.fput_object('my-bucketname', 'my-objectname-csv',
                       'my-filepath.csv', content_type='application/csv')
except ResponseError as err:
    print(err)

```
---------------------------------------
<a name="stat_object">
#### stat_object(bucket_name, object_name)
Get metadata of an object.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object

__Return Value__
   `obj`   _Object_ : object stat info for following format:
  * `obj.size` _int_: size of the object
  * `obj.etag` _string_: etag of the object
  * `obj.content_type` _string_: Content-Type of the object
  * `obj.last_modified` _time.time_: modified time stamp

__Example__
```py
# Fetch stats on your object.
try:
    print(client.stat_object('my-bucketname', 'my-objectname'))
except ResponseError as err:
    print(err)
```
---------------------------------------
<a name="remove_object">
#### remove_object(bucket_name, object_name)
Remove an object.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object

__Example__
```py
# Remove an object.
try:
    client.remove_object('my-bucketname', 'my-objectname')
except ResponseError as err:
    print(err)

```
---------------------------------------
<a name="remove_incomplete_upload">
#### remove_incomplete_upload(bucket_name, object_name)
Remove an partially uploaded object.

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object

__Example__
```py
# Remove an partially uploaded object.
try:
    client.remove_incomplete_upload('my-bucketname', 'my-objectname')
except ResponseError as err:
    print(err)
```

### Presigned operations
---------------------------------------
<a name="presigned_get_object">
#### presigned_get_object(bucket_name, object_name, expiry)
Generate a presigned URL for GET.

__Arguments__
* `bucket_name` _string_: name of the bucket.
* `object_name` _string_: name of the object.
* `expires` _datetime.datetime_: expiry in seconds.

__Example__
```py
from datetime import timedelta

# presigned get object URL for object name, expires in 2 days.
try:
    print(client.presigned_get_object('my-bucketname', 'my-objectname', expires=timedelta(days=2)))
# Response error is still possible since internally presigned does get bucket location.
except ResponseError as err:
    print(err)
```

---------------------------------------
<a name="presigned_put_object">
#### presigned_put_object(bucket_name, object_name, expires)
Generate a presigned URL for PUT.
<blockquote>
NOTE: you can upload to S3 only with specified object name.
</blockquote>

__Arguments__
* `bucket_name` _string_: name of the bucket
* `object_name` _string_: name of the object
* `expires` _datetime.datetime_: expiry in seconds

__Example__
```py
from datetime import timedelta

# presigned Put object URL for an object name, expires in 3 days.
try:
    print(client.presigned_put_object('my-bucketname',
                                      'my-objectname',
                                      expires=timedelta(days=3)))
# Response error is still possible since internally presigned does get
# bucket location.
except ResponseError as err:
    print(err)
```

---------------------------------------
<a name="presigned_post_policy">
#### presigned_post_policy(policy)
presigned_post_policy we can provide policies specifying conditions restricting
what you want to allow in a POST request, such as bucket name where objects can be
uploaded, key name prefixes that you want to allow for the object being created and more.

We need to create our policy first:
```py
from minio import PostPolicy
post_policy = PostPolicy()
```
Apply upload policy restrictions:
```py
# set bucket name location for uploads.
post_policy.set_bucket_name('my-bucketname')
# set key prefix for all incoming uploads.
post_policy.set_key_startswith('my-objectname')
# set content length for incoming uploads.
post_policy.set_content_length_range(10, 1024)

# set expiry 10 days into future.
expires_date = datetime.utcnow()+timedelta(days=10)
post_policy.set_expires(expires_date)

```
Get the POST form key/value object:
```py
try:
    url_str, signed_form_data = s3client.presigned_post_policy(post_policy)
except ResponseError as err:
    print(err)    
```

POST your content from the command line using `curl`:
```py
curl_str = 'curl -X POST {0}'.format(url_str)
curl_cmd = [curl_str]
for field in signed_form_data:
    curl_cmd.append('-F {0}={1}'.format(field, signed_form_data[field]))

    # print curl command to upload files.
    curl_cmd.append('-F file=@<FILE>')
    print(' '.join(curl_cmd))
```
