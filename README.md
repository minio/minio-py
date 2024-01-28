# Newtera Python Client SDK for Newtera TDM

The Newtera Python Client SDK provides high level APIs to access any Newtera TDM service.

This Quickstart Guide covers how to install the Newtera client SDK, connect to the Newtera TDM, and access the test data files.

The example below uses:
- [Python version 3.7+](https://www.python.org/downloads/) 
- The [Newtera `mc` command line tool](https://min.io/docs/Newtera/linux/reference/Newtera-mc.html)
- The Newtera TDM local server

For a complete list of APIs and examples, see the [Python Client API Reference](https://newtera.net/docs/Newtera/developers/python/API.html)

## Install the Newtera Python SDK

The Python SDK requires Python version 3.7+.
You can install the SDK with `pip` or from the [`Newtera/Newtera-py` GitHub repository](https://github.com/yong-zhang-newtera/Newtera-py):

### Using `pip`

```sh
pip3 install Newtera
```

### Using Source From GitHub

```sh
git clone https://github.com/yong-zhang-newtera/Newtera-py
cd Newtera-py
python setup.py install
```

## Create a Newtera Client

To connect to the target service, create a Newtera client using the `Newtera()` method with the following required parameters:

| Parameter    | Description                                            |
|--------------|--------------------------------------------------------|
| `endpoint`   | URL of the target service.                             |
| `access_key` | Access key (user ID) of a user account in the service. |
| `secret_key` | Secret key (password) for the user account.            |

For example:

```py
from Newtera import Newtera

client = Newtera("play.min.io",
    access_key="Q3AM3UQ867SPQQA43P2F",
    secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
)
```

## Example - File Uploader

This example does the following:

- Connects to the Newtera `play` server using the provided credentials.
- Creates a bucket named `python-test-bucket` if it does not already exist.
- Uploads a file named `test-file.txt` from `/tmp`, renaming it `my-test-file.txt`.
- Verifies the file was created using [`mc ls`](https://min.io/docs/Newtera/linux/reference/Newtera-mc/mc-ls.html).

### `file_uploader.py`

```py
# file_uploader.py Newtera Python SDK example
from Newtera import Newtera
from Newtera.error import S3Error

def main():
    # Create a client with the Newtera server playground, its access key
    # and secret key.
    client = Newtera("play.min.io",
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

    # The file to upload, change this path if needed
    source_file = "/tmp/test-file.txt"

    # The destination bucket and filename on the Newtera server
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

* [Examples](https://github.com/Newtera/Newtera-py/tree/master/examples)


## License

This SDK is distributed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
