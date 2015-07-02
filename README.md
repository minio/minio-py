# Minimal object storage library for Python [![Build Status](https://travis-ci.org/minio/minio-py.svg)](https://travis-ci.org/minio/minio-py)

## Install

```sh
$ pip install minio
```

## Example

```python
client = minio.Minio(‘https://s3.amazonaws.com’, access_key=’access_key’, secret_key=’secret_key’)
client.make_bucket(‘my_bucket’)

file_stat = os.stat(‘data.json’)
with open(‘data.json’, 'rb') as data_file:
    client.put_object(‘my_bucket’, 'data.json', file_stat.st_size, data_file)


objects = client.list_objects('my_bucket')
for obj in objects:
    print ‘object:‘, obj.key, obj.last_modified

object_data = client.get_object(bucket, 'hello/world')
for object_chunk in object_data:
    print object_chunk
```

## Examples:

TODO

## Join The Community
* Community hangout on Gitter    [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/minio/minio?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
* Ask questions on Quora  [![Quora](http://upload.wikimedia.org/wikipedia/commons/thumb/5/57/Quora_logo.svg/55px-Quora_logo.svg.png)](http://www.quora.com/Minio)

## Contribute

[Contributors Guide](./CONTRIBUTING.md)
