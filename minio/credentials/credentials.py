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
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass(frozen=True)
class Credentials:
    """
    Represents credentials access key, secret key and session token.
    """

    access_key: str
    secret_key: str
    session_token: Optional[str] = None
    expiration: Optional[datetime] = None

    def __post_init__(self):
        if not self.access_key:
            raise ValueError("Access key must not be empty")

        if not self.secret_key:
            raise ValueError("Secret key must not be empty")

        if self.expiration and self.expiration.tzinfo:
            object.__setattr__(
                self, "expiration",
                self.expiration.astimezone(timezone.utc).replace(tzinfo=None),
            )

    def is_expired(self) -> bool:
        """Check whether this credentials expired or not."""
        return (
            self.expiration < (datetime.utcnow() + timedelta(seconds=10))
            if self.expiration else False
        )
