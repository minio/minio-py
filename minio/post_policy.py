# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016 Minio, Inc.
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
minio.post_policy
~~~~~~~~~~~~~~~

This module contains :class:`PostPolicy <PostPolicy>` implementation.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import base64
import json
import datetime

from .helpers import (is_non_empty_string, is_valid_bucket_name)
from .error import InvalidArgumentError


# Policy explanation:
# http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
class PostPolicy(object):
    """
    A :class:`PostPolicy <PostPolicy>` object for constructing
       Amazon S3 POST policy JSON string.
    """
    def __init__(self):
        self._expiration = None
        self._content_length_range = tuple()
        # publicly accessible
        self.policies = []
        self.form_data = dict()
        self.bucket_name = ''
        self.key = ''

    def set_expires(self, time):
        """
        Set expiration time :class:`datetime.datetime`.

        :param time: set expiration :class:`datetime.datetime`.
        """
        if time.toordinal() < 1:
            ValueError()
        self._expiration = time

    def set_key(self, key):
        """
        Set key policy condition.

        :param key: set key name.
        """
        is_non_empty_string(key)

        self.policies.append(('eq', '$key', key))
        self.form_data['key'] = key
        self.key = key

    def set_key_startswith(self, key_startswith):
        """
        Set key startswith policy condition.

        :param key_startswith: set key prefix name.
        """
        is_non_empty_string(key_startswith)

        self.policies.append(('starts-with', '$key', key_startswith))
        self.form_data['key'] = key_startswith

    def set_bucket_name(self, bucket_name):
        """
        Set bucket name policy condition.

        :param bucket_name: set bucket name.
        """
        is_valid_bucket_name(bucket_name)

        self.policies.append(('eq', '$bucket', bucket_name))
        self.form_data['bucket'] = bucket_name
        self.bucket_name = bucket_name

    def set_content_type(self, content_type):
        """
        Set content-type policy condition.

        :param content_type: set content type name.
        """
        self.policies.append(('eq', '$Content-Type', content_type))
        self.form_data['Content-Type'] = content_type

    def set_content_length_range(self, min_length, max_length):
        """
        Set content length range policy condition.
           Raise :exc:`ValueError` for invalid inputs.

        :param min_length: Minimum length limit for content size.
        :param max_length: Maximum length limit for content size.
        """
        err_msg = ('Min-length ({}) must be <= Max-length ({}), '
                   'and they must be non-negative.').format(
                       min_length, max_length
                   )
        if min_length > max_length or min_length < 0 or max_length < 0:
            raise ValueError(err_msg)

        self._content_length_range = (min_length, max_length)

    def append_policy(self, condition, target, value):
        self.policies.append([condition, target, value])

    def _marshal_json(self, extras=()):
        """
        Marshal various policies into json str/bytes.
        """
        policies = self.policies[:]
        policies.extend(extras)
        if self._content_length_range:
            policies.append(['content-length-range'] +
                            list(self._content_length_range))

        policy_stmt = {
            "expiration": self._expiration.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"),
        }

        if len(policies) > 0:
            policy_stmt["conditions"] = policies

        return json.dumps(policy_stmt)

    def base64(self, extras=()):
        """
        Encode json into base64.
        """
        s = self._marshal_json(extras=extras)
        s_bytes = s if isinstance(s, bytes) else s.encode('utf-8')
        b64enc = base64.b64encode(s_bytes)
        return b64enc.decode('utf-8') if isinstance(b64enc, bytes) else b64enc

    def is_valid(self):
        """
        Validate for required parameters.
        """
        if not isinstance(self._expiration, datetime.datetime):
            raise InvalidArgumentError('Expiration datetime must be specified.')

        if 'key' not in self.form_data:
            raise InvalidArgumentError('object key must be specified.')

        if 'bucket' not in self.form_data:
            raise InvalidArgumentError('bucket name must be specified.')
