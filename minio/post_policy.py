# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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

import binascii

from .helpers import is_non_empty_string, is_valid_bucket_name, encode_to_base64

## Policy explanation: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
class PostPolicy(object):
    """
    PostPolicy provides strict static type conversion and validation for Amazon S3's POST policy JSON string.
    """
    def __init__(self):
        self._expiration = None
        self._content_length_range = tuple() ## TODO implement this
        ## publicly accessible
        self.policies = []
        self.form_data = dict()
        self.bucket = ''
        self.key = ''

    def set_expires(self, time):
        self._expiration = time

    def set_key(self, key):
        is_non_empty_string(key)
        policy = ('eq', '$key', key)
        self.policies.append(policy)
        self.form_data['key'] = key
        self.key = key

    def set_key_startswith(self, key_startswith):
        is_non_empty_string(key_startswith)
        policy = ('starts-with', '$key', key_startswith)
        self.policies.append(policy)
        self.form_data['key'] = key_startswith

    def set_bucket(self, bucket):
        is_valid_bucket_name(bucket)

        policy = ('eq', '$bucket', bucket)
        self.policies.append(policy)
        self.form_data['bucket'] = bucket
        self.bucket = bucket

    def set_content_type(self, content_type):
        policy = ('eq', '$Content-Type', bucket)
        self.policies.append(policy)
        self.form_data['Content-Type'] = content_type

    def _marshal_json(self):
        expiration_str = '"expiration":"' + self._expiration.strftime("%Y-%m-%dT%H:%M:%S.000Z") + '"'
        policies = []
        for p in self.policies:
            policies.append('["'+p[0]+'","'+p[1]+'","'+p[2]+'"]')

        if len(policies) > 0:
            policies_str = '"conditions":[' + ','.join(policies) + ']'

        return_str = '{'
        if len(expiration_str) > 0:
            return_str = return_str + expiration_str + ','

        if len(policies_str) > 0:
            return_str = return_str + policies_str

        return_str = return_str + '}'
        return bytearray(return_str)

    def base64(self):
        return encode_to_base64(self._marshal_json())

    def is_expiration_set(self):
        if self._expiration is None:
            return False
        return True

    def is_key_set(self):
        if self.form_data['key'] is None:
            return False
        return True

    def is_bucket_set(self):
        if self.form_data['bucket'] is None:
            return False
        return True
