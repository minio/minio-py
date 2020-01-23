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

from .credentials import Provider, Value

class Static(Provider):
    def __init__(self, access_key=None, secret_key=None, token=None):
        super(Static, self).__init__()
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = token

    def retrieve(self):
        return Value(
            access_key=self._access_key,
            secret_key=self._secret_key,
            session_token=self._session_token
        )

    def is_expired(self):
        return False