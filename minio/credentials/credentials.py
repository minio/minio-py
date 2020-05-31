# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2020 MinIO, Inc.
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

"""Credential definitions to access S3 service."""

from abc import ABCMeta, abstractmethod
from datetime import datetime


class Value:
    """
    Denotes credential values such as access key, secret key and session token.
    """

    def __init__(self, access_key, secret_key, session_token=None):
        self._access_key = access_key
        self._secret_key = secret_key
        self._session_token = session_token

    @property
    def access_key(self):
        """Get access key."""
        return self._access_key

    @property
    def secret_key(self):
        """Get secret key."""
        return self._secret_key

    @property
    def session_token(self):
        """Get session token."""
        return self._session_token


class Provider:  # pylint: disable=too-few-public-methods
    """Credential retriever."""
    __metaclass__ = ABCMeta

    @abstractmethod
    def retrieve(self):
        """Retrieve credential value and its expiry."""


class Credentials:  # pylint: disable=too-few-public-methods
    """Denotes credentials for S3 service."""

    def __init__(self, provider):
        self._provider = provider
        self._value = None
        self._expiry = None

    def get(self, force=False):
        """Get credentials from provider if needed."""
        if (
                force or
                not self._value or
                (self._expiry and self._expiry < datetime.utcnow())
        ):
            self._value, self._expiry = self._provider.retrieve()
        return self._value
