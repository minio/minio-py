# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017, 2018, 2019 MinIO, Inc.
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

import abc

class Value(object):
    def __init__(self, access_key=None, secret_key=None, session_token=None):
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token

        #TODO investigate signature type in python
        self._signer_type = None

class Provider(abc.ABC):
    @abc.abstractmethod
    def retrieve(self):
        pass

    @abc.abstractmethod
    def is_expired(self):
        pass

class Expiry(object):
    def __init__(self):
        # TODO
        self._expiration = None
    
    def current_time(self):
        #TODO
        pass

    def set_expiration(self, expiration, window):
        #TODO
        pass

    def is_expired(self):
        #TODO
        pass

class Credentials(object):
    # TODO: Investigate how to init this, go uses New func
    def __init__(self, forceRefresh=True, provider=None):
        self._creds = None
        self._forceRefresh = forceRefresh
        self._provider = provider
    # Check is expired?
    def get(self):
        if self.is_expired():
            try:
                creds = self._provider.retrieve()
            except:
                # TODO
                raise
            self._creds = creds
            self._forceRefresh = False
        return self._creds

    def expire(self):
        self._forceRefresh = True

    def is_expired(self):
        return self._forceRefresh or self._provider.is_expired()



