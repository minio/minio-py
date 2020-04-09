# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2020 MinIO, Inc.
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

import os
import json
import sys

from .credentials import Provider, Value


class FileMinioClient(Provider):
    def __init__(self, filename=None, alias=None, retrieved=False):
        super(Provider, self).__init__()
        self._filename = (
            filename or
            os.path.join(os.environ.get('HOME'),
                         'mc' if sys.platform == 'win32' else '.mc',
                         'config.json')
        )
        self._alias = alias or os.environ.get('MINIO_ALIAS') or "s3"
        self._retrieved = retrieved

    def retrieve(self):
        self._retrieved = False

        config = open(self._filename, 'r')
        doc = json.load(config)
        creds = doc['hosts'][self._alias]

        access_key = creds['accessKey']
        secret_key = creds['secretKey']

        self._retrieved = True

        return Value(
            access_key=access_key,
            secret_key=secret_key
        )

    def is_expired(self):
        return not self._retrieved
