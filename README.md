# MinIO Python Client SDK for Amazon S3 Compatible Cloud Storage [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io) [![Sourcegraph](https://sourcegraph.com/github.com/minio/minio-py/-/badge.svg)](https://sourcegraph.com/github.com/minio/minio-py?badge) [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/minio/minio-py/blob/master/LICENSE)

The MinIO Python Client SDK provides straightforward APIs to access any Amazon S3 compatible object storage.

This Quickstart Guide covers how to install the MinIO client SDK, connect to MinIO, and create a sample file uploader.
For a complete list of APIs and examples, see the [Python Client API Reference](https://min.io/docs/minio/linux/developers/python/API.html)

These examples presume a working [3.7+ Python development environment](https://www.python.org/downloads/) and the [MinIO `mc` command line tool](https://min.io/docs/minio/linux/reference/minio-mc.html).

## Install the Minio Python SDK

### Using pip

```sh
pip3 install minio
```

### From GitHub

```sh
git clone https://github.com/minio/minio-py
cd minio-py
python setup.py install
```

## Initialize a MinIO Client Object

The MinIO client requires the following parameters to connect to an Amazon S3 compatible object storage:

| Parameter  | Description                                            |
|------------|--------------------------------------------------------|
| Endpoint   | URL to S3 service.                                     |
| Access Key | Access key (user ID) of an account in the S3 service.  |
| Secret Key | Secret key (password) of an account in the S3 service. |

```py
from minio import Minio
from minio.error import S3Error


def main():
    # Create a client with the MinIO server playground, its access key          
    # and secret key.                                                           
    client = Minio(
        endpoint="play.min.io",
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

    print("MinIO Python SDK client initialized", client)

if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)
```

## Example - File Uploader

This sample code connects to an object storage server, creates a bucket, and uploads a file to the bucket.
It uses the MinIO `play` server, a public MinIO cluster located at [https://play.min.io](https://play.min.io).

The `play` server runs the latest stable version of MinIO and may be used for testing and development.
The access credentials shown in this example are open to the public and all data uploaded to `play` should be considered public and non-protected.

### `file_uploader.py`

This example does the following:

- Connects to the MinIO `play` server using the provided credentials.
- Creates a bucket named `minio-python-sdk-test-bucket`.
- Uploads a file named `minio-python-sdk-test-file.bin` from `/tmp`.
- Verifies the file was created using `mc ls`.

```py
# file_uploader.py MinIO Python SDK example

import os
from minio import Minio
from minio.error import S3Error

def main():
    # Create a client with the MinIO server playground, its access key
    # and secret key.
    client = Minio(
        endpoint="play.min.io",
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

    bucket_name = "minio-python-sdk-test-bucket"
    original_filename = "minio-python-sdk-test-file.bin"
    path = "/tmp"
    destination_filename = "my-test-file.bin"
    
    # Make the bucket if it doesn't exist.
    found = client.bucket_exists(bucket_name)
    if not found:
        client.make_bucket(bucket_name)
    else:
        print("Bucket", bucket_name, "already exists")

    # Upload the file, renaming it in the process

    original_full_path = os.path.join(path, original_filename)
    client.fput_object(
        bucket_name, destination_filename, original_full_path,
    )
    print(
        original_full_path, "successfully uploaded as object",
        destination_filename, "to bucket", bucket_name,
    )


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)
```

**1. Create a test file containing data:**

You can do this with `dd` on Linux or macOS systems:

```sh
dd if=/dev/urandom of=/tmp/minio-python-sdk-test-file.bin bs=2048 count=10
```

or `fsutil` on Windows:

```sh
fsutil file createnew "C:\Users\<username>\Desktop\minio-python-sdk-test-file.bin" 20480
```

**2. Run `file_uploader.py` with the following command:**

```sh
python file_uploader.py
```

The output resembles the following:

```sh
/tmp/minio-python-sdk-test-file.bin successfully uploaded as object my-test-file.bin to bucket minio-python-sdk-test-bucket
```

**3. Verify the Uploaded File With `mc ls`:**

```sh
mc ls play/minio-python-sdk-test-bucket
[2023-11-03 22:18:54 UTC]  20KiB STANDARD my-test-file.bin
```

## More References

* [Python Client API Reference](https://min.io/docs/minio/linux/developers/python/API.html)
* [Examples](https://github.com/minio/minio-py/tree/master/examples)

## Explore Further

* [Complete Documentation](https://min.io/docs/minio/kubernetes/upstream/index.html)

## Contribute

[Contributors Guide](https://github.com/minio/minio-py/blob/master/CONTRIBUTING.md)

## License

This SDK is distributed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0), see [LICENSE](https://github.com/minio/minio-py/blob/master/LICENSE) for more information.

[![PYPI](https://img.shields.io/pypi/v/minio.svg)](https://pypi.python.org/pypi/minio)

