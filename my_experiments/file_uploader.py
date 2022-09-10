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
    found = client.bucket_exists("hello")
    if not found:
        client.make_bucket("hello")
    else:
        print("Bucket 'hello' already exists")

    # Upload '/home/user/Photos/asiaphotos.zip' as object name
    # 'asiaphotos-2015.zip' to bucket 'asiatrip'.
    client.fput_object("hello", "hello_file", "H:\BITS M.E Computer Science\Semester 3\Cloud Computing\Repo\minio-py\my_experiments\hello_file.txt",)
    print("'H:\BITS M.E Computer Science\Semester 3\Cloud Computing\Repo\minio-py\my_experiments\hello_file.txt' is successfully uploaded as " "object 'hello_file' to bucket 'hello'.")
    print(client.get_bucket_encryption("hello"))


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)