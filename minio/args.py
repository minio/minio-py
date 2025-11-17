# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
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

# pylint: disable=invalid-name

"""Argument classes for APIs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import IO, Any, Optional

from typing_extensions import Protocol

from .compat import quote
from .models import Retention
from .sse import SseCustomerKey
from .time import to_http_header, to_iso8601utc


class Directive(str, Enum):
    """metadata and tagging directive."""
    COPY = "COPY"
    REPLACE = "REPLACE"


class ProgressType(Protocol):
    """typing stub for Put/Get object progress."""

    def set_meta(self, object_name: str, total_length: int):
        """Set process meta information."""

    def update(self, length: int):
        """Set current progress length."""


@dataclass(frozen=True)
class PutObjectFanOutEntry:
    """PutObjectFanOut entry."""
    key: str
    user_metadata: Optional[dict[str, str]] = None
    tags: Optional[dict[str, str]] = None
    content_type: Optional[str] = None
    content_encoding: Optional[str] = None
    content_disposition: Optional[str] = None
    content_language: Optional[str] = None
    cache_control: Optional[str] = None
    retention: Optional[Retention] = None

    def to_json(self) -> str:
        """Convert the entry to JSON string."""
        mapping: dict[str, Any] = {"key": self.key}
        if self.user_metadata:
            normalized = {}
            for key, value in self.user_metadata.items():
                key = (
                    key if key.lower().startswith("x-amz-meta-")
                    else ("x-amz-meta-" + key)
                )
                normalized[key] = value
            mapping["metadata"] = normalized
        if self.tags:
            mapping["tags"] = self.tags
        if self.content_type:
            mapping["contentType"] = self.content_type
        if self.content_encoding:
            mapping["contentEncoding"] = self.content_encoding
        if self.content_disposition:
            mapping["contentDisposition"] = self.content_disposition
        if self.content_language:
            mapping["contentLanguage"] = self.content_language
        if self.cache_control:
            mapping["cacheControl"] = self.cache_control
        if self.retention:
            mapping["retention"] = self.retention.mode
            mapping["retainUntil"] = to_iso8601utc(
                self.retention.retain_until_date,
            )
        return json.dumps(mapping)


@dataclass(frozen=True)
class SnowballObject:
    """A source object definition for upload_snowball_objects method."""
    object_name: str
    filename: Optional[str] = None
    data: Optional[IO[bytes]] = None
    length: Optional[int] = None
    mod_time: Optional[datetime] = None

    def __post_init__(self):
        if not (self.filename is not None) ^ (self.data is not None):
            raise ValueError("only one of filename or data must be provided")
        if self.data is not None and self.length is None:
            raise ValueError("length must be provided for data")
        if (
                self.mod_time is not None and
                not isinstance(self.mod_time, datetime)
        ):
            raise ValueError("mod_time must be datetime type")


@dataclass(frozen=True)
class SourceObject:
    """Source object for copy and compose object."""
    bucket_name: str
    object_name: str
    region: Optional[str] = None
    version_id: Optional[str] = None
    ssec: Optional[SseCustomerKey] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    match_etag: Optional[str] = None
    not_match_etag: Optional[str] = None
    modified_since: Optional[datetime] = None
    unmodified_since: Optional[datetime] = None

    def __post_init__(self):
        if (
                self.ssec is not None and
                not isinstance(self.ssec, SseCustomerKey)
        ):
            raise ValueError("ssec must be SseCustomerKey type")
        if self.offset is not None and self.offset < 0:
            raise ValueError("offset should be zero or greater")
        if self.length is not None and self.length <= 0:
            raise ValueError("length should be greater than zero")
        if self.match_etag is not None and self.match_etag == "":
            raise ValueError("match_etag must not be empty")
        if self.not_match_etag is not None and self.not_match_etag == "":
            raise ValueError("not_match_etag must not be empty")
        if (
                self.modified_since is not None and
                not isinstance(self.modified_since, datetime)
        ):
            raise ValueError("modified_since must be datetime type")
        if (
                self.unmodified_since is not None and
                not isinstance(self.unmodified_since, datetime)
        ):
            raise ValueError("unmodified_since must be datetime type")

    def make_copy_headers(self) -> dict[str, str]:
        """Generate copy source headers."""
        copy_source = quote("/" + self.bucket_name + "/" + self.object_name)
        if self.version_id:
            copy_source += "?versionId=" + quote(self.version_id)

        headers = {"x-amz-copy-source": copy_source}
        if self.ssec:
            headers.update(self.ssec.copy_headers())
        if self.match_etag:
            headers["x-amz-copy-source-if-match"] = self.match_etag
        if self.not_match_etag:
            headers["x-amz-copy-source-if-none-match"] = self.not_match_etag
        if self.modified_since:
            headers["x-amz-copy-source-if-modified-since"] = (
                to_http_header(self.modified_since)
            )
        if self.unmodified_since:
            headers["x-amz-copy-source-if-unmodified-since"] = (
                to_http_header(self.unmodified_since)
            )
        return headers
