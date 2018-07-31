import base64
from io import BytesIO
import hashlib

from minio.api import Minio

AWSAccessKeyId = ''
AWSSecretKey = ''

STORAGE_ENDPOINT = 's3.amazonaws.com'
STORAGE_BUCKET = ''


def main():
    content = BytesIO(b'Hello again')

    key = b'32byteslongsecretkeymustprovided'
    encryption_key = base64.b64encode(key).decode()
    encryption_key_md5 = base64.b64encode(hashlib.md5(key).digest()).decode()

    minio = Minio(STORAGE_ENDPOINT, access_key=AWSAccessKeyId, secret_key=AWSSecretKey)

    # Put object with special headers which encrypt object in S3 with provided key
    minio.put_object(STORAGE_BUCKET, 'test_crypt.txt', content, content.getbuffer().nbytes,
                     metadata={
                         'x-amz-server-side-encryption-customer-algorithm': 'AES256',
                         'x-amz-server-side-encryption-customer-key': encryption_key,
                         'x-amz-server-side-encryption-customer-key-MD5': encryption_key_md5
                     })

    # Get decrypted object with same headers
    obj = minio.get_object(STORAGE_BUCKET, 'test_crypt1.txt', request_headers={
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': encryption_key,
        'x-amz-server-side-encryption-customer-key-MD5': encryption_key_md5
    })

    print(obj.read())

if __name__ == '__main__':
    main()
