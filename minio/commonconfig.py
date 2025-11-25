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

"""Common request/response configuration of S3 APIs."""
# pylint: disable=invalid-name

from __future__ import absolute_import, annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import IO, Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .error import MinioException
from .helpers import quote
from .sse import SseCustomerKey
from .time import to_http_header
from .xml import SubElement, find, findall, findtext

COPY = "COPY"
REPLACE = "REPLACE"
DISABLED = "Disabled"
ENABLED = "Enabled"
GOVERNANCE = "GOVERNANCE"
COMPLIANCE = "COMPLIANCE"
_MAX_KEY_LENGTH = 128
_MAX_VALUE_LENGTH = 256
_MAX_OBJECT_TAG_COUNT = 10
_MAX_TAG_COUNT = 50

A = TypeVar("A", bound="Tags")


class Tags(dict):
    """dict extended to bucket/object tags."""

    def __init__(self, for_object: bool = False):
        self._for_object = for_object
        super().__init__()

    def __setitem__(self, key: str, value: str):
        limit = _MAX_OBJECT_TAG_COUNT if self._for_object else _MAX_TAG_COUNT
        if len(self) == limit:
            tag_type = "object" if self._for_object else "bucket"
            raise ValueError(f"only {limit} {tag_type} tags are allowed")
        if not key or len(key) > _MAX_KEY_LENGTH or "&" in key:
            raise ValueError(f"invalid tag key '{key}'")
        if value is None or len(value) > _MAX_VALUE_LENGTH or "&" in value:
            raise ValueError(f"invalid tag value '{value}'")
        super().__setitem__(key, value)

    @classmethod
    def new_bucket_tags(cls: Type[A]) -> A:
        """Create new bucket tags."""
        return cls()

    @classmethod
    def new_object_tags(cls: Type[A]) -> A:
        """Create new object tags."""
        return cls(True)

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        elements = findall(element, "Tag")
        obj = cls()
        for tag in elements:
            key = cast(str, findtext(tag, "Key", True))
            value = cast(str, findtext(tag, "Value", True))
            obj[key] = value
        return obj

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        for key, value in self.items():
            tag = SubElement(element, "Tag")
            SubElement(tag, "Key", key)
            SubElement(tag, "Value", value)
        return element


B = TypeVar("B", bound="Tag")


@dataclass(frozen=True)
class Tag:
    """Tag."""

    key: str
    value: str

    def __post_init__(self):
        if not self.key:
            raise ValueError("key must be provided")
        if self.value is None:
            raise ValueError("value must be provided")

    @classmethod
    def fromxml(cls: Type[B], element: ET.Element) -> B:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Tag", True))
        key = cast(str, findtext(element, "Key", True))
        value = cast(str, findtext(element, "Value", True))
        return cls(key, value)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Tag")
        SubElement(element, "Key", self.key)
        SubElement(element, "Value", self.value)
        return element


C = TypeVar("C", bound="AndOperator")


@dataclass(frozen=True)
class AndOperator:
    """AND operator."""

    prefix: Optional[str] = None
    tags: Optional[Tags] = None

    def __post_init__(self):
        if self.prefix is None and not self.tags:
            raise ValueError("at least prefix or tags must be provided")

    @classmethod
    def fromxml(cls: Type[C], element: ET.Element) -> C:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "And", True))
        prefix = findtext(element, "Prefix")
        tags = (
            None if find(element, "Tag") is None
            else Tags.fromxml(element)
        )
        return cls(prefix, tags)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "And")
        if self.prefix is not None:
            SubElement(element, "Prefix", self.prefix)
        if self.tags is not None:
            self.tags.toxml(element)
        return element


D = TypeVar("D", bound="Filter")


@dataclass(frozen=True)
class Filter:
    """Lifecycle rule filter."""

    and_operator: Optional[AndOperator] = None
    prefix: Optional[str] = None
    tag: Optional[Tag] = None

    def __post_init__(self):
        valid = (
            (self.and_operator is not None) ^
            (self.prefix is not None) ^
            (self.tag is not None)
        )
        if not valid:
            raise ValueError("only one of and, prefix or tag must be provided")

    @classmethod
    def fromxml(cls: Type[D], element: ET.Element) -> D:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Filter", True))
        and_operator = (
            None if find(element, "And") is None
            else AndOperator.fromxml(element)
        )
        prefix = findtext(element, "Prefix")
        tag = None if find(element, "Tag") is None else Tag.fromxml(element)
        return cls(and_operator, prefix, tag)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Filter")
        if self.and_operator:
            self.and_operator.toxml(element)
        if self.prefix is not None:
            SubElement(element, "Prefix", self.prefix)
        if self.tag is not None:
            self.tag.toxml(element)
        return element


@dataclass(frozen=True)
class BaseRule(ABC):
    """Base rule class for Replication and Lifecycle."""
    status: str
    rule_filter: Optional[Filter] = None
    rule_id: Optional[str] = None

    def __post_init__(self):
        check_status(self.status)
        if self.rule_id is not None:
            self.rule_id = self.rule_id.strip()
            if not self.rule_id:
                raise ValueError("rule ID must be non-empty string")
            if len(self.rule_id) > 255:
                raise ValueError("rule ID must not exceed 255 characters")

    @abstractmethod
    def _require_subclass_implementation(self) -> None:
        """Dummy abstract method to enforce abstract class behavior."""

    @staticmethod
    def parsexml(
            element: ET.Element,
    ) -> tuple[str, Optional[Filter], Optional[str]]:
        """Parse XML and return filter and ID."""
        return (
            cast(str, findtext(element, "Status", True)),
            (
                None if find(element, "Filter") is None
                else Filter.fromxml(element)
            ),
            findtext(element, "ID"),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        SubElement(element, "Status", self.status)
        if self.rule_filter:
            self.rule_filter.toxml(element)
        if self.rule_id is not None:
            SubElement(element, "ID", self.rule_id)
        return element


def check_status(status: str):
    """Validate status."""
    if status not in [ENABLED, DISABLED]:
        raise ValueError("status must be 'Enabled' or 'Disabled'")


@dataclass
class ObjectConditionalReadArgs(ABC):
    """Base argument class holds condition properties for reading object."""
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

    @abstractmethod
    def _require_subclass_implementation(self) -> None:
        """Dummy abstract method to enforce abstract class behavior."""

    def gen_copy_headers(self) -> dict[str, str]:
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


E = TypeVar("E", bound="CopySource")


@dataclass
class CopySource(ObjectConditionalReadArgs):
    """A source object definition for copy_object method."""

    def _require_subclass_implementation(self) -> None:
        """Dummy abstract method to enforce abstract class behavior."""

    @classmethod
    def of(cls: Type[E], src: ObjectConditionalReadArgs) -> E:
        """Create CopySource from another source."""
        return cls(
            bucket_name=src.bucket_name,
            object_name=src.object_name,
            region=src.region,
            version_id=src.version_id,
            ssec=src.ssec,
            offset=src.offset,
            length=src.length,
            match_etag=src.match_etag,
            not_match_etag=src.not_match_etag,
            modified_since=src.modified_since,
            unmodified_since=src.unmodified_since,
        )


F = TypeVar("F", bound="ComposeSource")


@dataclass
class ComposeSource(ObjectConditionalReadArgs):
    """A source object definition for compose_object method."""
    _object_size: Optional[int] = field(default=None, init=False)
    _headers: Optional[dict[str, str]] = field(default=None, init=False)

    def _require_subclass_implementation(self) -> None:
        """Dummy abstract method to enforce abstract class behavior."""

    def _validate_size(self, object_size: int):
        """Validate object size with offset and length."""
        def make_error(name, value):
            ver = ("?versionId="+self.version_id) if self.version_id else ""
            return ValueError(
                f"Source {self.bucket_name}/{self.object_name}{ver}: "
                f"{name} {value} is beyond object size {object_size}"
            )

        if self.offset is not None and self.offset >= object_size:
            raise make_error("offset", self.offset)
        if self.length is not None:
            if self.length > object_size:
                raise make_error("length", self.length)
            offset = self.offset or 0
            if offset+self.length > object_size:
                raise make_error("compose size", offset+self.length)

    def build_headers(self, object_size: int, etag: str):
        """Build headers."""
        self._validate_size(object_size)
        self._object_size = object_size
        headers = self.gen_copy_headers()
        headers["x-amz-copy-source-if-match"] = self.match_etag or etag
        self._headers = headers

    @property
    def object_size(self) -> Optional[int]:
        """Get object size."""
        if self._object_size is None:
            raise MinioException(
                "build_headers() must be called prior to "
                "this method invocation",
            )
        return self._object_size

    @property
    def headers(self) -> dict[str, str]:
        """Get headers."""
        if self._headers is None:
            raise MinioException(
                "build_headers() must be called prior to "
                "this method invocation",
            )
        return self._headers.copy()

    @classmethod
    def of(cls: Type[F], src: ObjectConditionalReadArgs) -> F:
        """Create ComposeSource from another source."""
        return cls(
            bucket_name=src.bucket_name,
            object_name=src.object_name,
            region=src.region,
            version_id=src.version_id,
            ssec=src.ssec,
            offset=src.offset,
            length=src.length,
            match_etag=src.match_etag,
            not_match_etag=src.not_match_etag,
            modified_since=src.modified_since,
            unmodified_since=src.unmodified_since,
        )


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
