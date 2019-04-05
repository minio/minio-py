# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C) 2018 MinIO, Inc.
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
from minio.sse import SSE_C
from minio.sse import copy_SSE_C

AWSAccessKeyId = 'YOUR-ACCESSKEYID'
AWSSecretKey = 'YOUR-SECRETACCESSKEY'

STORAGE_ENDPOINT = 's3.amazonaws.com'
STORAGE_BUCKET = 'test-encryption-bucket'


def main():
    content = BytesIO(b'Hello again')

    minio = Minio(STORAGE_ENDPOINT, access_key=AWSAccessKeyId, secret_key=AWSSecretKey)

    # Create an SSE-C object with a 32 byte customer_key
    key = b'32byteslongsecretkeymustprovided'
    sse_customer_key = SSE_C(key)

    # Put object with SSE_C object passed as a param 
    minio.put_object(STORAGE_BUCKET, 'test_crypt.txt', content, content.getbuffer().nbytes, sse=sse_customer_key)

    # Create a a copy_SSE-C object to copy an object from source to destination object on the Server-Side
    copy_sse_customer_key = copy_SSE_C(key)

    #Copy encrypted object on Server-Side from Source to Destination
    obj = minio.copy_object(STORAGE_BUCKET, 'test_crypt_copy.txt', STORAGE_BUCKET+'/test_crypt.txt', 
    source_sse=copy_sse_customer_key, sse=sse_customer_key)

    # Get decrypted object with SSE_C object passed in as param
    obj = minio.get_object(STORAGE_BUCKET, 'test_crypt_copy.txt', sse=sse_customer_key)

    print(obj.read())

if __name__ == '__main__':
    main()
