# MinIO Python Client SDK for Amazon S3 Compatible Cloud Storage [![Slack](https://slack.min.io/slack?type=svg)](https://slack.min.io) [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/minio/minio-py/blob/master/LICENSE)

The MinIO Python Client SDK provides high level APIs to access any MinIO Object Storage or other Amazon S3 compatible service.

This Quickstart Guide covers how to install the MinIO client SDK, connect to the object storage service, and create a sample file uploader.

The example below uses:
- [Python version 3.7+](https://www.python.org/downloads/) 
- The [MinIO `mc` command line tool](https://min.io/docs/minio/linux/reference/minio-mc.html)
- The MinIO `play` test server

The `play` server is a public MinIO cluster located at [https://play.min.io](https://play.min.io).
This cluster runs the latest stable version of MinIO and may be used for testing and development.
The access credentials in the example are open to the public and all data uploaded to `play` should be considered public and world-readable.

For a complete list of APIs and examples, see the [Python Client API Reference](https://min.io/docs/minio/linux/developers/python/API.html)

## Install the MinIO Python SDK

The Python SDK requires Python version 3.7+.
You can install the SDK with `pip` or from the [`minio/minio-py` GitHub repository](https://github.com/minio/minio-py):

### Using `pip`

```sh
pip3 install minio
```

### Using Source From GitHub

```sh
git clone https://github.com/minio/minio-py
cd minio-py
python setup.py install
```

## Create a MinIO Client

To connect to the target service, create a MinIO client using the `Minio()` method with the following required parameters:

| Parameter    | Description                                            |
|--------------|--------------------------------------------------------|
| `endpoint`   | URL of the target service.                             |
| `access_key` | Access key (user ID) of a user account in the service. |
| `secret_key` | Secret key (password) for the user account.            |

For example:

```py
from minio import Minio

client = Minio("play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)
```

## Example - File Uploader

This example does the following:

- Connects to the MinIO `play` server using the provided credentials.
- Creates a bucket named `python-test-bucket` if it does not already exist.
- Uploads a file named `test-file.txt` from `/tmp`, renaming it `my-test-file.txt`.
- Verifies the file was created using [`mc ls`](https://min.io/docs/minio/linux/reference/minio-mc/mc-ls.html).

### `file_uploader.py`

```py
# file_uploader.py MinIO Python SDK example
from minio import Minio
from minio.error import S3Error

def main():
    # Create a client with the MinIO server playground, its access key
    # and secret key.
    client = Minio("play.min.io",
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

    # The file to upload, change this path if needed
    source_file = "/tmp/test-file.txt"

    # The destination bucket and filename on the MinIO server
    bucket_name = "python-test-bucket"
    destination_file = "my-test-file.txt"
    
    # Make the bucket if it doesn't exist.
    found = client.bucket_exists(bucket_name)
    if not found:
        client.make_bucket(bucket_name)
        print("Created bucket", bucket_name)
    else:
        print("Bucket", bucket_name, "already exists")

    # Upload the file, renaming it in the process
    client.fput_object(
        bucket_name, destination_file, source_file,
    )
    print(
        source_file, "successfully uploaded as object",
        destination_file, "to bucket", bucket_name,
    )

if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)
```

To run this example:

1. Create a file in `/tmp` named `test-file.txt`.
   To use a different path or filename, modify the value of `source_file`.

2. Run `file_uploader.py` with the following command:

```sh
python file_uploader.py
```

If the bucket does not exist on the server, the output resembles the following:

```sh
Created bucket python-test-bucket
/tmp/test-file.txt successfully uploaded as object my-test-file.txt to bucket python-test-bucket
```

3. Verify the uploaded file with `mc ls`:

```sh
mc ls play/python-test-bucket
[2023-11-03 22:18:54 UTC]  20KiB STANDARD my-test-file.txt
```

## More References

* [Python Client API Reference](https://min.io/docs/minio/linux/developers/python/API.html)
* [Examples](https://github.com/minio/minio-py/tree/master/examples)

## Explore Further

* [Complete Documentation](https://min.io/docs/minio/kubernetes/upstream/index.html)

## Contribute

[Contributors Guide](https://github.com/minio/minio-py/blob/master/CONTRIBUTING.md)

## License

This SDK is distributed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0), see [LICENSE](https://github.com/minio/minio-py/blob/master/LICENSE) and [NOTICE](https://github.com/minio/minio-go/blob/master/NOTICE) for more information.

[![PYPI](https://img.shields.io/pypi/v/minio.svg)](https://pypi.python.org/pypi/minio)
