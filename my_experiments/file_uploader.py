from minio import Minio
from minio.error import S3Error
from minio.api import *
import csv

def main():
    # Create a client with the MinIO server playground, its access key
    # and secret key.
    client = Minio(
        "play.min.io",
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

    # Make 'asiatrip' bucket if not exist.
    found=client.bucket_exists("testbucket")
    if not found:
        client.make_bucket("testbucket")
    else:
        # client.remove_bucket("hello")
        # client.make_bucket("hello")
        print("Bucket {} already exists".format("testbucket"))

    client.fput_object("testbucket","test_file","H:\BITS M.E Computer Science\Semester 3\Cloud Computing\Repo\minio-py\my_experiments\hello_file.txt",)
    client.fput_object("testbucket","sub_log_file","H:\BITS M.E Computer Science\Semester 3\Cloud Computing\Repo\minio-py\my_experiments\sub_log_file.csv",)
    # print("'H:\BITS M.E Computer Science\Semester 3\Cloud Computing\Repo\minio-py\my_experiments\hello_file.txt' is successfully uploaded as " "object 'hello_file' to bucket 'hello'.")
    # print(client.get_bucket_encryption("hello"))
    # buckets = client.list_buckets()
    # for bucket in buckets:
    #     print(bucket.name,bucket.creation_date)
    # client.create_sub_log_file("testbucket")
    objects=client.list_objects("testbucket")
    for obj in objects:
        print(obj)
    client.fget_object("testbucket","test_file","hello_file.txt")
    client.fget_object("testbucket","sub_log_file","sub_log_file.csv")
    with client.select_object_content(
        "my-bucket",
        "my-object.csv",
        SelectRequest(
            "select * from S3Object",
            CSVInputSerialization(),
            CSVOutputSerialization(),
            request_progress=True,
        ),
    ) as result:
        for data in result.stream():
            print(data.decode())
        print(result.stats())
    # try:
    #     response=client.get_object("testbucket","sub_log_file")
    #     # Read data from response.
    #     print(response.data)
    # finally:
    #     response.close()
    #     response.release_conn()


if __name__ == "__main__":
    try:
        main()
    except S3Error as exc:
        print("error occurred.", exc)