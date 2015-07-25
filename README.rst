# Minio Python Library for Amazon S3 compatible cloud storage

## Install

The recommended technique for installing this package is through pip.

```sh
$ pip install minio
```

## Example

```python
#!/usr/bin/env python

from minio.minio import Minio

# Instantiate a client
client = Minio('https://s3.amazonaws.com',
                access_key='access_key',
                secret_key='secret_key')

# List buckets
buckets = client.list_buckets()
for bucket in buckets:
    print 'bucket:', bucket.name, bucket.creation_date

```

## Join The Community
* Community hangout on Gitter   https://gitter.im/minio/minio
* Ask questions on Quora  https://www.quora.com/Minio
