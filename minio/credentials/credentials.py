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

from abc import ABCMeta, abstractmethod
from datetime import datetime, timedelta

class Value(object):
    def __init__(self, access_key=None, secret_key=None, session_token=None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

class Provider(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def retrieve(self):
        pass

    @abstractmethod
    def is_expired(self):
        pass

class Expiry(object):
    def __init__(self):
        self._expiration = None

    def set_expiration(self, expiration, time_delta=None):
        self._expiration = expiration
        if time_delta is not None:
            self._expiration = self._expiration + time_delta

    def is_expired(self):
        if self._expiration is None:
            return True
        return self._expiration < datetime.now()

class Credentials(object):
    def __init__(self, forceRefresh=True, provider=None):
        self._creds = None
        self._forceRefresh = forceRefresh
        self._provider = provider

    def get(self):
        if self.is_expired():
            try:
                creds = self._provider.retrieve()
            except:
                raise
            self._creds = creds
            self._forceRefresh = False
        return self._creds

    def expire(self):
        self._forceRefresh = True

    def is_expired(self):
        return self._forceRefresh or self._provider.is_expired()
