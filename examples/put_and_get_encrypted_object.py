# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2019 MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Note: YOUR-ACCESSKEYID, YOUR-SECRETACCESSKEY and my-bucketname are
# dummy values, please replace them with original values.

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

    minio = Minio(STORAGE_ENDPOINT, access_key=AWSAccessKeyId,
                  secret_key=AWSSecretKey)

    # Put object with special headers which encrypt object in S3 with provided
    # key
    minio.put_object(
        STORAGE_BUCKET, 'test_crypt.txt', content, content.getbuffer().nbytes,
        metadata={
            'x-amz-server-side-encryption-customer-algorithm': 'AES256',
            'x-amz-server-side-encryption-customer-key': encryption_key,
            'x-amz-server-side-encryption-customer-key-MD5': encryption_key_md5
        })

    # Get decrypted object with same headers
    obj = minio.get_object(
        STORAGE_BUCKET, 'test_crypt1.txt',
        request_headers={
            'x-amz-server-side-encryption-customer-algorithm': 'AES256',
            'x-amz-server-side-encryption-customer-key': encryption_key,
            'x-amz-server-side-encryption-customer-key-MD5': encryption_key_md5
        })

    print(obj.read())


if __name__ == '__main__':
    main()
