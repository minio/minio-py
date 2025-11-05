# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015-2019 MinIO, Inc.
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

# pylint: disable=too-many-lines

"""
minio.error
~~~~~~~~~~~~~~~~~~~

This module provides custom exception classes for MinIO library
and API specific errors.

:copyright: (c) 2015, 2016, 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import, annotations

from typing import Optional, Type, TypeVar
from xml.etree import ElementTree as ET

try:
    from urllib3.response import BaseHTTPResponse  # type: ignore[attr-defined]
except ImportError:
    from urllib3.response import HTTPResponse as BaseHTTPResponse

from .xml import findtext


class MinioException(Exception):
    """Base Minio exception."""


class InvalidResponseError(MinioException):
    """Raised to indicate that non-xml response from server."""

    def __init__(
            self, code: int, content_type: Optional[str], body: Optional[str],
    ):
        self._code = code
        self._content_type = content_type
        self._body = body
        super().__init__(
            f"non-XML response from server; Response code: {code}, "
            f"Content-Type: {content_type}, Body: {body}"
        )

    def __reduce__(self):
        return type(self), (self._code, self._content_type, self._body)


class ServerError(MinioException):
    """Raised to indicate that S3 service returning HTTP server error."""

    def __init__(self, message: str, status_code: int):
        self._status_code = status_code
        super().__init__(message)

    @property
    def status_code(self) -> int:
        """Get HTTP status code."""
        return self._status_code


A = TypeVar("A", bound="S3Error")


class S3Error(MinioException):
    """
    Raised to indicate that error response is received
    when executing S3 operation.
    """
    response: BaseHTTPResponse
    code: Optional[str]
    message: Optional[str]
    resource: Optional[str]
    request_id: Optional[str]
    host_id: Optional[str]
    bucket_name: Optional[str]
    object_name: Optional[str]

    _EXC_MUTABLES = {"__traceback__", "__context__", "__cause__"}

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        response: BaseHTTPResponse,
        code: Optional[str],
        message: Optional[str],
        resource: Optional[str],
        request_id: Optional[str],
        host_id: Optional[str],
        bucket_name: Optional[str] = None,
        object_name: Optional[str] = None,
    ):
        object.__setattr__(self, "response", response)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "host_id", host_id)
        object.__setattr__(self, "bucket_name", bucket_name)
        object.__setattr__(self, "object_name", object_name)

        bucket_message = f", bucket_name: {bucket_name}" if bucket_name else ""
        object_message = f", object_name: {object_name}" if object_name else ""

        super().__init__(
            f"S3 operation failed; code: {code}, message: {message}, "
            f"resource: {resource}, request_id: {request_id}, "
            f"host_id: {host_id}{bucket_message}{object_message}"
        )

        # freeze after init
        object.__setattr__(self, "_is_frozen", True)

    def __setattr__(self, name, value):
        if name in self._EXC_MUTABLES:
            object.__setattr__(self, name, value)
            return
        if getattr(self, "_is_frozen", False):
            raise AttributeError(
                f"{self.__class__.__name__} is frozen and "
                "does not allow attribute assignment"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        if name in self._EXC_MUTABLES:
            object.__delattr__(self, name)
            return
        if getattr(self, "_is_frozen", False):
            raise AttributeError(
                f"{self.__class__.__name__} is frozen and "
                "does not allow attribute deletion"
            )
        object.__delattr__(self, name)

    @classmethod
    def fromxml(cls: Type[A], response: BaseHTTPResponse) -> A:
        """Create new object with values from XML element."""
        element = ET.fromstring(response.data.decode())
        return cls(
            response=response,
            code=findtext(element, "Code"),
            message=findtext(element, "Message"),
            resource=findtext(element, "Resource"),
            request_id=findtext(element, "RequestId"),
            host_id=findtext(element, "HostId"),
            bucket_name=findtext(element, "BucketName"),
            object_name=findtext(element, "Key"),
        )

    def copy(self, code: str, message: str) -> S3Error:
        """Make a copy with replaced code and message."""
        return S3Error(
            response=self.response,
            code=code,
            message=message,
            resource=self.resource,
            request_id=self.request_id,
            host_id=self.host_id,
            bucket_name=self.bucket_name,
            object_name=self.object_name,
        )

    def __repr__(self):
        return (
            f"S3Error(code={self.code!r}, message={self.message!r}, "
            f"resource={self.resource!r}, request_id={self.request_id!r}, "
            f"host_id={self.host_id!r}, bucket_name={self.bucket_name!r}, "
            f"object_name={self.object_name!r})"
        )

    def __eq__(self, other):
        if not isinstance(other, S3Error):
            return NotImplemented
        return (
            self.code == other.code
            and self.message == other.message
            and self.resource == other.resource
            and self.request_id == other.request_id
            and self.host_id == other.host_id
            and self.bucket_name == other.bucket_name
            and self.object_name == other.object_name
        )

    def __hash__(self):
        return hash(
            (
                self.code,
                self.message,
                self.resource,
                self.request_id,
                self.host_id,
                self.bucket_name,
                self.object_name,
            )
        )


class MinioAdminException(Exception):
    """Raised to indicate admin API execution error."""

    def __init__(self, code: str, body: str):
        self._code = code
        self._body = body
        super().__init__(
            f"admin request failed; Status: {code}, Body: {body}",
        )

    def __reduce__(self):
        return type(self), (self._code, self._body)
