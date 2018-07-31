# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2018 Minio, Inc.
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

"""
minio.sse
~~~~~~~~~~~~~~~~~~~

This module contains core API parsers.

:copyright: (c) 2018 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""
import base64
import hashlib
import json
from .error import (InvalidArgumentError, InvalidSizeError, InvalidXMLError, NoSuchBucketPolicy)

class SSE_C(object):

    def __init__(self, key):
        self.key = key
        if len(self.key) != 32:
            raise InvalidSizeError("SSE-C keys need to be 256 bit base64 encoded")
    
    def type(self):
        return "SSE-C"
    
    def marshal(self):

        b64key = base64.b64encode(self.key)
        md5 = hashlib.md5()
        md5.update(self.key)
        md5_key = base64.b64encode(md5.digest()).decode()
        keys = {
            "X-Amz-Server-Side-Encryption-Customer-Algorithm": "AES256",
            "X-Amz-Server-Side-Encryption-Customer-Key": b64key.decode(),
            "X-Amz-Server-Side-Encryption-Customer-Key-MD5": md5_key
            }

        return keys

class copy_SSE_C(object):

    def __init__(self, key):
        self.key = key
        if len(self.key) != 32:
            raise InvalidArgumentError("Length of Customer key must be 32 Bytes")

    def type(self):
        return "copy_SSE-C"

    def marshal(self):
        b64key = base64.b64encode(self.key)
        md5 = hashlib.md5()
        md5.update(self.key)
        md5_key = base64.b64encode(md5.digest()).decode()
        keys = {
            "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm":"AES256",
            "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key": b64key.decode(),
            "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-MD5": md5_key
        }
        return keys


class SSE_KMS(object):
    def __init__(self, key, context):
        self.key = key
        self.context = context

    def type(self):
        return "SSE-KMS"

    def marshal(self):
        keys = {
            "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id": self.key,
            "X-Amz-Server-Side-Encryption":"aws:kms"
        }

        if self.context:
                ctx_str = json.dumps(self.context)
                ctx_str = bytes(ctx_str, 'utf-8')
                b64key = base64.b64encode(ctx_str)
                header = {"X-Amz-Server-Side-Encryption-Context": b64key.decode()}
                keys.update(header)
        
        return keys
        

class SSE_S3(object):
    def type(self):
        return "SSE-S3"

    def marshal(self):
        keys = {
            "X-Amz-Server-Side-Encryption":"AES256"
        }
        return keys
    
