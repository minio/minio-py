# MinIO Python SDK for Amazon S3 Compatible Cloud Storage [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io)

MinIO Python SDK is Simple Storage Service (aka S3) client to perform bucket and object operations to any Amazon S3 compatible object storage service.

For a complete list of APIs and examples, please take a look at the [Python Client API Reference](https://min.io/docs/minio/linux/developers/python/API.html)

## Minimum Requirements
Python 3.7 or higher.

## Download using pip

```sh
pip3 install minio
```

## Download source

```sh
git clone https://github.com/minio/minio-py
cd minio-py
python setup.py install
```

## Quick Start Example - File Uploader
This example program connects to an S3-compatible object storage server, make a bucket on that server, and upload a file to the bucket.

You need the following items to connect to an S3-compatible object storage server:

| Parameters | Description                                                |
|------------|------------------------------------------------------------|
| Endpoint   | URL to S3 service.                                         |
| Access Key | Access key (aka user ID) of an account in the S3 service.  |
| Secret Key | Secret key (aka password) of an account in the S3 service. |

This example uses MinIO server playground [https://play.min.io](https://play.min.io). Feel free to use this service for test and development.

### file_uploader.py
```py
from minio import Minio
from minio.error import S3Error


def main():
    # Create a client with the MinIO server playground, its access key
    # and secret key.
    client = Minio(
        "play.min.io",
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

    # Make 'asiatrip' bucket if not exist.
    found = client.bucket_exists("asiatrip")
    if not found:
        client.make_bucket("asiatrip")
    else:
        print("Bucket 'asiatrip' already exists")

    # Upload '/home/user/Photos/asiaphotos.zip' as object name
    # 'asiaphotos-2015.zip' to bucket 'asiatrip'.
    client.fput_object(
        "asiatrip", "asiaphotos-2015.zip", "/home/user/Photos/asiaphotos.zip",
    )
    print(
        "'/home/user/Photos/asiaphotos.zip' is successfully uploaded as "
        "object 'asiaphotos-2015.zip' to bucket 'asiatrip'."
    )


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)
```

#### Run File Uploader
```sh
$ python file_uploader.py
'/home/user/Photos/asiaphotos.zip' is successfully uploaded as object 'asiaphotos-2015.zip' to bucket 'asiatrip'.

$ mc ls play/asiatrip/
[2016-06-02 18:10:29 PDT]  82KiB asiaphotos-2015.zip
```

## More References
* [Python Client API Reference](https://min.io/docs/minio/linux/developers/python/API.html)
* [Examples](https://github.com/minio/minio-py/tree/master/examples)

## Explore Further
* [Complete Documentation](https://min.io/docs/minio/kubernetes/upstream/index.html)

## Contribute
Please refer [Contributors Guide](https://github.com/minio/minio-py/blob/master/CONTRIBUTING.md)

[![PYPI](https://img.shields.io/pypi/v/minio.svg)](https://pypi.python.org/pypi/minio)
