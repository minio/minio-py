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

from .credentials import Provider, Value


class EnvMinio(Provider):
    def __init__(self, retrieved=False):
        super(Provider, self).__init__()
        self._retrieved = retrieved

    def retrieve(self):
        self._retrieved = False
        access_key = os.environ.get('MINIO_ACCESS_KEY')
        secret = os.environ.get('MINIO_SECRET_KEY')
        self._retrieved = True

        return Value(
            access_key=access_key,
            secret_key=secret
        )

    def is_expired(self):
        return not self._retrieved
