### Bucket Exists
*code:*

```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

try:
    print(client.bucket_exists('mybucket'))
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python bucket_exists.py
True
```
### fget
*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Get a full object
try:
    client.fget_object('mybucket', 'myobject', 'localfile.txt')
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python fget_object.py
```

### fput

*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Put an object 'my-objectname' with contents from 'my-filepath'
try:
    client.fput_object('mybucket', 'myobject', 'myfile.txt')
except ResponseError as err:
    print(err)

# Put on object 'my-objectname-csv' with contents from
# 'my-filepath.csv' as 'application/csv'.
try:
    client.fput_object('my-bucketname', 'my-objectname-csv',
                       'myfile.csv', content_type='application/csv')
except ResponseError as err:
    print(err)
```
*Running the example*
```
 $ python fput_object.py
```
### List Buckets

*code:*
```
from minio import Minio

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG', insecure=False )

buckets = client.list_buckets()

for bucket in buckets:
    print(bucket.name, bucket.creation_date)
```
*Running the example*
```
$ python list_buckets.py
('aaron', datetime.datetime(2016, 2, 8, 19, 47, 12, 453000, tzinfo=<UTC>))
('dee', datetime.datetime(2016, 3, 18, 0, 2, 4, 181000, tzinfo=<UTC>))
('flib', datetime.datetime(2016, 1, 31, 17, 23, 7, 757000, tzinfo=<UTC>))
('images-eu-vm224', datetime.datetime(2016, 3, 10, 10, 0, 4, 557000, tzinfo=<UTC>))
('kline', datetime.datetime(2016, 3, 23, 0, 14, 4, 137000, tzinfo=<UTC>))
('mark', datetime.datetime(2016, 2, 5, 13, 53, 52, 717000, tzinfo=<UTC>))
('mc-binaries', datetime.datetime(2016, 2, 8, 2, 19, 39, 69000, tzinfo=<UTC>))
('minio-binaries', datetime.datetime(2016, 2, 18, 21, 0, 42, 229000, tzinfo=<UTC>))
('my-bucketname', datetime.datetime(2016, 3, 23, 2, 47, 48, 641000, tzinfo=<UTC>))
('mybucket', datetime.datetime(2016, 3, 23, 2, 47, 47, 185000, tzinfo=<UTC>))
('newbucket', datetime.datetime(2016, 1, 29, 1, 23, 11, 525000, tzinfo=<UTC>))
('rmskd', datetime.datetime(2016, 3, 21, 20, 27, 17, 465000, tzinfo=<UTC>))
('s3git-test', datetime.datetime(2016, 3, 20, 16, 8, 36, 589000, tzinfo=<UTC>))
('test', datetime.datetime(2016, 2, 29, 23, 30, 15, 765000, tzinfo=<UTC>))
('test123', datetime.datetime(2016, 1, 28, 5, 19, 18, 829000, tzinfo=<UTC>))
('testhelen', datetime.datetime(2016, 2, 27, 4, 9, 11, 861000, tzinfo=<UTC>))
```
### Make a bucket
*code:*
```
client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
# Make a new bucket
try:
    client.make_bucket('mybucketname')
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python make_bucket.py
```
### Remove Object
*code:*
```from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Remove an object.
try:
    client.remove_object('mybucket', 'myobject')
except ResponseError as err:
    print(err)
else:
    print("Removed myobject successfully.")

```
*Running the example*
```
 python remove_object.py
 Removed myobject successfully.
```

### List incomplete upload
*code:*
```
from minio import Minio

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

uploads = client.list_incomplete_uploads('mybucket',
                                         prefix='bucket',
                                         recursive=True)
for obj in uploads:
    print(obj.bucket_name, obj.object_name, obj.upload_id, obj.size)
```
*Running the example*
```
 $ python list_incomplete_uploads.py
 ('mybucket', 'bucket.mov', 'N7_Ydesb34PIYQIy5Sho5bbrCjSytMRXq03xuNm3d-jIQA8', 0)
```
### Remove incomplete upload
*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Remove an partially uploaded object.
try:
    client.remove_incomplete_upload('mybucket', 'bucket.mov')
except ResponseError as err:
    print(err)
```
*Running the example*
```
 $ python remove_incomplete_upload.py
```
### Stat of an object
*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

### Fetch stats on your object.
try:
    print(client.stat_object('mybucket', 'myobject'))
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python stat_object.py
<Object: bucket_name: mybucket object_name: myobject last_modified: 1458685132.0 etag:  size: 14 content_type: application/octet-stream, is_dir: False>
```
### Get Object to local filesystem
*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Get a full object
try:
    data = client.get_object('mybucket', 'myobject')
    with open('my-testfile', 'wb') as file_data:
        for d in data:
            file_data.write(d)
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python  get_object.py
```
### Get partial object
*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Offset the download by 2 bytes and retrieve a total of 4 bytes.
try:
    data = client.get_partial_object('mybucket', 'myobject', 2, 4)
    with open('my-testfile', 'wb') as file_data:
        for d in data:
            file_data.write(d)
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python  get_partial_object.py
```

Pre-signed get object
*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# presigned get object URL for object name, expires in 7 days.
try:
    print(client.presigned_get_object('mybucket', 'myobject'))
# Response error is still possible since internally presigned does get
# bucket location.
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python presigned_get_object.py
https://play.minio.io:9000/mybucket/myobject?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=Q3AM3UQ867SPQQA43P2F%2F20160323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20160323T042519Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=3d1647f4915c5bfa1815177bbfbe62af13bedd83694fe17cc7e29163c07aecb1
```
### presigned put object
*code:*
```
import datetime

from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# presigned Put object URL for an object name, expires in 3 days.
try:
    print(client.presigned_put_object('mybucket',
                                      'myobject',
                                      datetime.timedelta(days=3)))
# Response error is still possible since internally presigned does get
# bucket location.
except ResponseError as err:
    print(err)
```
*Running the example*
```
 $ python presigned_put_object.py
 https://play.minio.io:9000/mybucket/myobject?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=Q3AM3UQ867SPQQA43P2F%2F20160323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20160323T043244Z&X-Amz-Expires=259200&X-Amz-SignedHeaders=host&X-Amz-Signature=782456b36d872755ee26369bf4adce24d0613c91da225ed759faa44ea8c5d448
```
Using the presigned put object
```
curl -X PUT -d "Hello World" "https://play.minio.io:9000/mybucket/myobject?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=Q3AM3UQ867SPQQA43P2F%2F20160323%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20160323T043244Z&X-Amz-Expires=259200&X-Amz-SignedHeaders=host&X-Amz-Signature=782456b36d872755ee26369bf4adce24d0613c91da225ed759faa44ea8c5d448"
```
### Remove bucket

*code:*
```
from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')
# Remove a bucket
# This operation will only work if your bucket is empty.
try:
    client.remove_bucket('mybucket')
except ResponseError as err:
    print(err)
```
*Running the example*
```
$ python remove_bucket.py
```

### Put object to a bucket
*code:*
```
import os

from minio import Minio
from minio.error import ResponseError

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# Put a file with default content-type.
try:
    file_stat = os.stat('localfile.txt')
    file_data = open('localfile.txt', 'rb')
    client.put_object('mybucket', 'myobject', file_data, file_stat.st_size)
except ResponseError as err:
    print(err)
else:
    print("Uploaded localfile.txt, successfully.")

# Put a file with 'application/csv'
try:
    file_stat = os.stat('localfile.csv')
    file_data = open('localfile.csv', 'rb')
    client.put_object('mybucket', 'myobject', file_data,
                      file_stat.st_size, content_type='application/csv')
except ResponseError as err:
    print(err)
else:
    print("Uploaded localfile.csv, successfully.")
```
*Running the example*
```
$ python put_object.py
Uploaded localfile.txt, successfully.
Uploaded localfile.csv, successfully.
```
### Presigned post policy

*code:*
```
```
*Running the example*
```
curl https://play.minio.io:9000/mybucket -F x-amz-algorithm=AWS4-HMAC-SHA256 -F key=myobject -F bucket=mybucket -F x-amz-signature=979f520ea5db8441db362ab1fc584d36cd43411a96939e9c2e94f2f435daa471 -F x-amz-date=20160323T050542Z -F policy=eyJleHBpcmF0aW9uIjoiMjAxNi0wNC0wMlQwNTowNTo0Mi4wMDBaIiwiY29uZGl0aW9ucyI6W1siZXEiLCIkYnVja2V0IiwibXlidWNrZXQiXSxbInN0YXJ0cy13aXRoIiwiJGtleSIsIm15b2JqZWN0Il0sWyJlcSIsIiR4LWFtei1kYXRlIiwiMjAxNjAzMjNUMDUwNTQyWiJdLFsiZXEiLCIkeC1hbXotYWxnb3JpdGhtIiwiQVdTNC1ITUFDLVNIQTI1NiJdLFsiZXEiLCIkeC1hbXotY3JlZGVudGlhbCIsIlEzQU0zVVE4NjdTUFFRQTQzUDJGLzIwMTYwMzIzL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QiXSxbImNvbnRlbnQtbGVuZ3RoLXJhbmdlIiwgMTAsIDEwMjRdXX0= -F x-amz-credential=Q3AM3UQ867SPQQA43P2F/20160323/us-east-1/s3/aws4_request -F file=@<FILE>
```
>Note: Replace '``<FILE>``' with any 'local filename'
### List Objects
*code:*
```
from minio import Minio

client = Minio('play.minio.io:9000',
               access_key='Q3AM3UQ867SPQQA43P2F',
               secret_key='zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG')

# List all object paths in bucket that begin with my-prefixname.
objects = client.list_objects('mybucket', prefix='myfilename',
                              recursive=True)
for obj in objects:
    print(obj.bucket_name, obj.object_name.encode('utf-8'), obj.last_modified,
          obj.etag, obj.size, obj.content_type)
```
*Running the example*
```
$ python list_objects.py
('mybucket', 'myfilename.txt', datetime.datetime(2016, 3, 23, 3, 50, 57, 169000, tzinfo=<UTC>), None, 14, None)
```


