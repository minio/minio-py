import base64
from io import BytesIO
import hashlib

from minio.api import Minio
from minio.sse import SSE_C

AWSAccessKeyId = '<Access Key>'
AWSSecretKey = '<Secret Key>'

STORAGE_ENDPOINT = 'play.minio.io:9000'
STORAGE_BUCKET = 'test-encryption-bucket'


def main():
    content = BytesIO(b'Hello again')

    key = b'32byteslongsecretkeymustprovided'
    encryption_key = base64.b64encode(key).decode()
    encryption_key_md5 = base64.b64encode(hashlib.md5(key).digest()).decode()

    minio = Minio(STORAGE_ENDPOINT, access_key=AWSAccessKeyId, secret_key=AWSSecretKey)

    sse_customer_key = SSE_C(key)

    # Put object with special headers from SSE_C object which encrypt object in S3 with provided key 
    minio.put_object(STORAGE_BUCKET, 'test_crypt.txt', content, content.getbuffer().nbytes, sse=sse_customer_key)

     # Get decrypted object with same headers
    obj = minio.get_object(STORAGE_BUCKET, 'test_crypt.txt', sse=sse_customer_key)

   
    print(obj.read())

if __name__ == '__main__':
    main()
