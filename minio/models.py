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

# pylint: disable=too-many-lines disable=invalid-name

"""API request, response, result and configuration."""

from __future__ import annotations

import base64
import json
from abc import ABC
from binascii import crc32
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from io import BufferedIOBase, BytesIO
from typing import Any, List, Optional, Tuple, Type, TypeVar, Union, cast
from urllib.parse import unquote_plus

from .checksum import Algorithm
from .checksum import Type as ChecksumType
from .compat import HTTPHeaderDict, HTTPResponse, JSONDecodeError
from .credentials import Credentials
from .error import MinioException
from .helpers import check_bucket_name
from .signer import get_credential_string, post_presign_v4
from .time import (from_http_header, from_iso8601utc, to_amz_date,
                   to_http_header, to_iso8601utc)
from .xml import ET, Element, SubElement, find, findall, findtext, unmarshal

################################################################################
###########                    Common data structures                ###########
################################################################################


@dataclass(frozen=True)
class Checksum:
    """Object checksum information."""
    checksum_crc32: Optional[str] = None
    checksum_crc32c: Optional[str] = None
    checksum_crc64nvme: Optional[str] = None
    checksum_sha1: Optional[str] = None
    checksum_sha256: Optional[str] = None
    checksum_type: Optional[str] = None

    def headers(self) -> HTTPHeaderDict:
        """Generate headers for checksum values."""
        headers = HTTPHeaderDict()
        for algorithm, value in (
            ("crc32", self.checksum_crc32),
            ("crc32c", self.checksum_crc32c),
            ("crc64nvme", self.checksum_crc64nvme),
            ("sha1", self.checksum_sha1),
            ("sha256", self.checksum_sha256),
        ):
            if value:
                headers[f"x-amz-checksum-algorithm-{algorithm}"] = value
                headers["x-amz-checksum-algorithm"] = algorithm
        return headers

    @classmethod
    def fromxml(cls: Type[Checksum], element: ET.Element) -> Checksum:
        """Create new object with values from XML element."""
        return cls(
            checksum_crc32=findtext(element, "ChecksumCRC32"),
            checksum_crc32c=findtext(element, "ChecksumCRC32C"),
            checksum_crc64nvme=findtext(element, "ChecksumCRC64NVME"),
            checksum_sha1=findtext(element, "ChecksumSHA1"),
            checksum_sha256=findtext(element, "ChecksumSHA256"),
            checksum_type=findtext(element, "ChecksumType"),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        for tag, text in (
            ("ChecksumCRC32", self.checksum_crc32),
            ("ChecksumCRC32C", self.checksum_crc32c),
            ("ChecksumCRC64NVME", self.checksum_crc64nvme),
            ("ChecksumSHA1", self.checksum_sha1),
            ("ChecksumSHA256", self.checksum_sha256),
        ):
            if text:
                SubElement(element, tag, text)
        return element


@dataclass(frozen=True)
class Filter:
    """Filter rule."""
    and_operator: Optional[And] = None
    prefix: Optional[str] = None
    tag: Optional[Tag] = None

    def __post_init__(self):
        if not (
            (self.and_operator is not None) ^
            (self.prefix is not None) ^
            (self.tag is not None)
        ):
            raise ValueError(
                "only one of and operator, prefix or tag must be provided",
            )

    @classmethod
    def fromxml(cls: Type[Filter], element: ET.Element) -> Filter:
        """Create new object with values from XML element."""
        return cls(
            and_operator=(
                None if find(element, "And") is None
                else Filter.And.fromxml(cast(ET.Element, find(element, "And")))
            ),
            prefix=findtext(element, "Prefix"),
            tag=(
                None if find(element, "Tag") is None
                else Tag.fromxml(cast(ET.Element, find(element, "Tag")))
            ),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        if self.and_operator:
            self.and_operator.toxml(SubElement(element, "And"))
        if self.prefix is not None:
            SubElement(element, "Prefix", self.prefix)
        if self.tag is not None:
            self.tag.toxml(SubElement(element, "Tag"))
        return element

    @dataclass(frozen=True)
    class And:
        """AND operator."""
        prefix: Optional[str] = None
        tags: Optional[Tags] = None

        def __post_init__(self):
            if self.prefix is None and not self.tags:
                raise ValueError("at least prefix or tags must be provided")

        @classmethod
        def fromxml(cls: Type[Filter.And], element: ET.Element) -> Filter.And:
            """Create new object with values from XML element."""
            return cls(
                prefix=findtext(element, "Prefix"),
                tags=(
                    None if find(element, "Tag") is None
                    else Tags.fromxml(element)
                ),
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.prefix is not None:
                SubElement(element, "Prefix", self.prefix)
            if self.tags is not None:
                self.tags.toxml(element)
            return element


@dataclass(frozen=True)
class Object:
    """Object information."""
    bucket_name: str
    object_name: Optional[str]
    last_modified: Optional[datetime] = None
    etag: Optional[str] = None
    size: Optional[int] = None
    metadata: Optional[Union[dict[str, str], HTTPHeaderDict]] = None
    version_id: Optional[str] = None
    is_latest: Optional[str] = None
    storage_class: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    content_type: Optional[str] = None
    is_delete_marker: bool = False
    tags: Optional[Tags] = None
    is_dir: bool = field(default=False, init=False)
    checksum_algorithms: Optional[List[str]] = None
    checksum_type: Optional[str] = None
    is_restore_in_progress: bool = False
    restore_expiry_date: Optional[datetime] = None

    def __post_init__(self):
        object.__setattr__(
            self,
            "is_dir",
            bool(self.object_name and self.object_name.endswith("/")),
        )

    @classmethod
    def fromxml(
            cls: Type[Object],
            element: ET.Element,
            bucket_name: str,
            is_delete_marker: bool = False,
            encoding_type: Optional[str] = None,
    ) -> Object:
        """Create new object with values from XML element."""
        tag = findtext(element, "LastModified")
        last_modified = None if tag is None else from_iso8601utc(tag)

        tag = findtext(element, "ETag")
        etag = None if tag is None else tag.replace('"', "")

        tag = findtext(element, "Size")
        size = None if tag is None else int(tag)

        elem = find(element, "Owner")
        owner_id, owner_name = (
            (None, None) if elem is None
            else (findtext(elem, "ID"), findtext(elem, "DisplayName"))
        )

        elems: ET.Element | list = find(element, "UserMetadata") or []
        metadata: dict[str, str] = {}
        for child in elems:
            key = child.tag.split("}")[1] if "}" in child.tag else child.tag
            metadata[key] = child.text or ""

        object_name = cast(str, findtext(element, "Key", True))
        if encoding_type == "url":
            object_name = unquote_plus(object_name)

        tags_text = findtext(element, "UserTags")
        tags: Optional[Tags] = None
        if tags_text:
            tags = Tags.new_object_tags()
            tags.update(
                cast(
                    List[Tuple[Any, Any]],
                    [tokens.split("=") for tokens in tags_text.split("&")],
                ),
            )

        checksum_algorithms = [
            elem.text for elem in findall(element, "ChecksumAlgorithm")
            if elem.text
        ]
        checksum_type = findtext(element, "ChecksumType")

        is_restore_in_progress = cast(
            str,
            findtext(element, "RestoreStatus/IsRestoreInProgress", default=""),
        )

        restore_expiry_date = findtext(
            element, "RestoreStatus/RestoreExpiryDate",
        )

        return cls(
            bucket_name=bucket_name,
            object_name=object_name,
            last_modified=last_modified,
            etag=etag,
            size=size,
            version_id=findtext(element, "VersionId"),
            is_latest=findtext(element, "IsLatest"),
            storage_class=findtext(element, "StorageClass"),
            owner_id=owner_id,
            owner_name=owner_name,
            metadata=metadata,
            is_delete_marker=is_delete_marker,
            tags=tags,
            checksum_algorithms=checksum_algorithms or None,
            checksum_type=checksum_type,
            is_restore_in_progress=is_restore_in_progress.lower() == "true",
            restore_expiry_date=(
                from_iso8601utc(restore_expiry_date) if restore_expiry_date
                else None
            ),
        )


def parse_list_objects(
        response: HTTPResponse,
        bucket_name: Optional[str] = None,
) -> tuple[list[Object], bool, Optional[str], Optional[str]]:
    """Parse ListObjects/ListObjectsV2/ListObjectVersions response."""
    element = ET.fromstring(response.data.decode())
    bucket_name = cast(str, findtext(element, "Name", True))
    encoding_type = findtext(element, "EncodingType")
    elements = findall(element, "Contents")
    objects = [
        Object.fromxml(tag, bucket_name, encoding_type=encoding_type)
        for tag in elements
    ]
    marker = objects[-1].object_name if objects else None

    elements = findall(element, "Version")
    objects += [
        Object.fromxml(tag, bucket_name, encoding_type=encoding_type)
        for tag in elements
    ]

    elements = findall(element, "CommonPrefixes")
    objects += [
        Object(
            bucket_name,
            unquote_plus(cast(str, findtext(tag, "Prefix", True)))
            if encoding_type == "url" else findtext(tag, "Prefix", True),
        ) for tag in elements
    ]

    elements = findall(element, "DeleteMarker")
    objects += [
        Object.fromxml(tag, bucket_name, is_delete_marker=True,
                       encoding_type=encoding_type)
        for tag in elements
    ]

    is_truncated = cast(
        str, findtext(element, "IsTruncated", default="")).lower() == "true"
    key_marker = findtext(element, "NextKeyMarker")
    if key_marker and encoding_type == "url":
        key_marker = unquote_plus(key_marker)
    version_id_marker = findtext(element, "NextVersionIdMarker")
    continuation_token = findtext(element, "NextContinuationToken")
    if key_marker is not None:
        continuation_token = key_marker
    if continuation_token is None:
        continuation_token = findtext(element, "NextMarker")
        if continuation_token and encoding_type == "url":
            continuation_token = unquote_plus(continuation_token)
    if continuation_token is None and is_truncated:
        continuation_token = marker
    return objects, is_truncated, continuation_token, version_id_marker


@dataclass(frozen=True)
class Part(Checksum):
    """Part information of a multipart upload."""
    part_number: int = 0
    etag: str = ""
    last_modified: Optional[datetime] = None
    size: Optional[int] = None

    @classmethod
    def fromxml(cls: Type[Part], element: ET.Element) -> Part:
        """Create new object with values from XML element."""
        part_number = int(cast(str, findtext(element, "PartNumber", True)))
        etag = cast(str, findtext(element, "ETag", True)).replace('"', "")
        tag = findtext(element, "LastModified")
        last_modified = from_iso8601utc(tag) if tag else None
        tag = findtext(element, "Size")
        size = int(tag) if tag else None
        checksum = Checksum.fromxml(element)
        return cls(
            part_number=part_number,
            etag=etag,
            last_modified=last_modified,
            size=size,
            **vars(checksum),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        SubElement(element, "PartNumber", str(self.part_number))
        SubElement(element, "ETag", f'"{self.etag}"')
        super().toxml(element)
        return element

    @classmethod
    def new(
            cls: Type[Part],
            result: CopyPartResult,
            part_number: int,
    ) -> Part:
        """Create new object by CopyPartResult."""
        return cls(
            part_number=part_number,
            **vars(result),
        )


StatusT = TypeVar("StatusT", bound="Status")


@dataclass(frozen=True)
class Status(ABC):
    """Status."""
    DISABLED = "Disabled"
    ENABLED = "Enabled"
    status: str

    @staticmethod
    def check(status: str):
        """Validate status."""
        if status not in [Status.ENABLED, Status.DISABLED]:
            raise ValueError(
                f"status must be {Status.ENABLED} or {Status.DISABLED}",
            )

    @classmethod
    def fromxml(cls: Type[StatusT], element: ET.Element) -> StatusT:
        """Create new object with values from XML element."""
        return cls(
            status=cast(str, findtext(element, "Status", True)),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        SubElement(element, "Status", self.status)
        return element


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
    def fromxml(cls: Type[Tag], element: ET.Element) -> Tag:
        """Create new object with values from XML element."""
        return cls(
            key=cast(str, findtext(element, "Key", True)),
            value=cast(str, findtext(element, "Value", True)),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        SubElement(element, "Key", self.key)
        SubElement(element, "Value", self.value)
        return element


class Tags(dict):
    """dict extended to bucket/object tags."""
    _MAX_KEY_LENGTH = 128
    _MAX_VALUE_LENGTH = 256
    _MAX_OBJECT_TAG_COUNT = 10
    _MAX_TAG_COUNT = 50

    def __init__(self, for_object: bool = False):
        self._for_object = for_object
        super().__init__()

    def __setitem__(self, key: str, value: str):
        limit = (
            self._MAX_OBJECT_TAG_COUNT
            if self._for_object else self._MAX_TAG_COUNT
        )
        if len(self) == limit:
            tag_type = "object" if self._for_object else "bucket"
            raise ValueError(f"only {limit} {tag_type} tags are allowed")
        if not key or len(key) > self._MAX_KEY_LENGTH or "&" in key:
            raise ValueError(f"invalid tag key '{key}'")
        if value is None or len(value) > self._MAX_VALUE_LENGTH or "&" in value:
            raise ValueError(f"invalid tag value '{value}'")
        super().__setitem__(key, value)

    @classmethod
    def new_bucket_tags(cls: Type[Tags]) -> Tags:
        """Create new bucket tags."""
        return cls()

    @classmethod
    def new_object_tags(cls: Type[Tags]) -> Tags:
        """Create new object tags."""
        return cls(True)

    @classmethod
    def fromxml(cls: Type[Tags], element: ET.Element) -> Tags:
        """Create new object with values from XML element."""
        obj = cls()
        for tag in findall(element, "Tag"):
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


################################################################################
###########                API configuration XML models              ###########
################################################################################


@dataclass(frozen=True)
class CORSConfig:
    """CORS configuration."""
    rules: Optional[List[CORSRule]] = None

    @classmethod
    def fromxml(cls: Type[CORSConfig], element: ET.Element) -> CORSConfig:
        """Create new object with values from XML element."""
        return cls(
            rules=[
                CORSConfig.CORSRule.fromxml(elem)
                for elem in findall(element, "CORSRule")
            ],
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("CORSConfiguration")
        for rule in self.rules or []:
            rule.toxml(SubElement(element, "CORSRule"))
        return element

    @dataclass(frozen=True)
    class CORSRule:
        """CORS rule."""
        allowed_headers: Optional[List[str]] = None
        allowed_methods: Optional[List[str]] = None
        allowed_origins: Optional[List[str]] = None
        expose_headers:  Optional[List[str]] = None
        id: Optional[str] = None
        max_age_seconds: Optional[int] = None

        @classmethod
        def fromxml(
                cls: Type[CORSConfig.CORSRule],
                element: ET.Element,
        ) -> CORSConfig.CORSRule:
            """Create new object with values from XML element."""
            max_age_seconds = findtext(element, "MaxAgeSeconds")
            return cls(
                allowed_headers=[
                    elem.text for elem in findall(element, "AllowedHeader")
                    if elem.text
                ],
                allowed_methods=[
                    elem.text for elem in findall(element, "AllowedMethod")
                    if elem.text
                ],
                allowed_origins=[
                    elem.text for elem in findall(element, "AllowedOrigin")
                    if elem.text
                ],
                expose_headers=[
                    elem.text for elem in findall(element, "ExposeHeader")
                    if elem.text
                ],
                id=findtext(element, "ID"),
                max_age_seconds=(
                    int(max_age_seconds) if max_age_seconds else None
                ),
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            for value in self.allowed_headers or []:
                SubElement(element, "AllowedHeader", value)
            for value in self.allowed_methods or []:
                SubElement(element, "AllowedMethod", value)
            for value in self.allowed_origins or []:
                SubElement(element, "AllowedOrigin", value)
            for value in self.expose_headers or []:
                SubElement(element, "ExposeHeader", value)
            if self.id:
                SubElement(element, "ID", self.id)
            if self.max_age_seconds is not None:
                SubElement(element, "MaxAgeSeconds", str(self.max_age_seconds))
            return element


@dataclass(frozen=True)
class LegalHold:
    """Legal hold configuration."""
    status: bool = False

    @classmethod
    def fromxml(cls: Type[LegalHold], element: ET.Element) -> LegalHold:
        """Create new object with values from XML element."""
        status = findtext(element, "Status")
        return cls(status=status == "ON")

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("LegalHold")
        SubElement(element, "Status", "ON" if self.status is True else "OFF")
        return element


@dataclass(frozen=True)
class LifecycleConfig:
    """Lifecycle configuration."""
    rules: list[Rule]

    @classmethod
    def fromxml(
            cls: Type[LifecycleConfig],
            element: ET.Element,
    ) -> LifecycleConfig:
        """Create new object with values from XML element."""
        return cls(
            rules=[
                LifecycleConfig.Rule.fromxml(tag)
                for tag in findall(element, "Rule")
            ],
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("LifecycleConfiguration")
        for rule in self.rules:
            rule.toxml(SubElement(element, "Rule"))
        return element

    @dataclass(frozen=True)
    class DateDays(ABC):
        """Base class holds date and days of Transition and Expiration."""
        date: Optional[datetime] = None
        days: Optional[int] = None

        @staticmethod
        def parsexml(
                element: ET.Element,
        ) -> tuple[Optional[datetime], Optional[int]]:
            """Parse XML to date and days."""
            date = from_iso8601utc(findtext(element, "Date"))
            days = findtext(element, "Days")
            return date, int(days) if days else None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.date is not None:
                SubElement(
                    element, "Date", to_iso8601utc(self.date),
                )
            if self.days:
                SubElement(element, "Days", str(self.days))
            return element

    @dataclass(frozen=True)
    class Transition(DateDays):
        """Transition."""
        storage_class: Optional[str] = None

        @classmethod
        def fromxml(
                cls: Type[LifecycleConfig.Transition],
                element: ET.Element,
        ) -> LifecycleConfig.Transition:
            """Create new object with values from XML element."""
            date, days = cls.parsexml(element)
            return cls(date, days, findtext(element, "StorageClass"))

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            super().toxml(element)
            if self.storage_class:
                SubElement(element, "StorageClass", self.storage_class)
            return element

    @dataclass(frozen=True)
    class NoncurrentVersionTransition:
        """Noncurrent version transition."""
        noncurrent_days: Optional[int] = None
        storage_class: Optional[str] = None
        newer_noncurrent_versions: Optional[int] = None

        @classmethod
        def fromxml(
                cls: Type[LifecycleConfig.NoncurrentVersionTransition],
                element: ET.Element,
        ) -> LifecycleConfig.NoncurrentVersionTransition:
            """Create new object with values from XML element."""
            noncurrent_days = findtext(element, "NoncurrentDays")
            versions = findtext(element, "NewerNoncurrentVersions")
            return cls(
                noncurrent_days=(
                    int(noncurrent_days) if noncurrent_days else None
                ),
                storage_class=findtext(element, "StorageClass"),
                newer_noncurrent_versions=int(versions) if versions else None,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.noncurrent_days:
                SubElement(element, "NoncurrentDays",
                           str(self.noncurrent_days))
            if self.storage_class:
                SubElement(element, "StorageClass", self.storage_class)
            if self.newer_noncurrent_versions:
                SubElement(element, "NewerNoncurrentVersions",
                           str(self.newer_noncurrent_versions))
            return element

    @dataclass(frozen=True)
    class NoncurrentVersionExpiration:
        """Noncurrent version expiration."""
        noncurrent_days: Optional[int] = None
        newer_noncurrent_versions: Optional[int] = None

        @classmethod
        def fromxml(
                cls: Type[LifecycleConfig.NoncurrentVersionExpiration],
                element: ET.Element,
        ) -> LifecycleConfig.NoncurrentVersionExpiration:
            """Create new object with values from XML element."""
            noncurrent_days = findtext(element, "NoncurrentDays")
            versions = findtext(element, "NewerNoncurrentVersions")
            return cls(
                noncurrent_days=(
                    int(noncurrent_days) if noncurrent_days else None
                ),
                newer_noncurrent_versions=int(versions) if versions else None,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.noncurrent_days:
                SubElement(element, "NoncurrentDays",
                           str(self.noncurrent_days))
            if self.newer_noncurrent_versions:
                SubElement(element, "NewerNoncurrentVersions",
                           str(self.newer_noncurrent_versions))
            return element

    @dataclass(frozen=True)
    class Expiration(DateDays):
        """Expiration."""
        expired_object_delete_marker: Optional[bool] = None

        @classmethod
        def fromxml(
                cls: Type[LifecycleConfig.Expiration],
                element: ET.Element,
        ) -> LifecycleConfig.Expiration:
            """Create new object with values from XML element."""
            date, days = cls.parsexml(element)
            expired_object_delete_marker = cast(
                str,
                findtext(element, "ExpiredObjectDeleteMarker", default=""),
            )
            if expired_object_delete_marker is None:
                return cls(date, days, None)

            if expired_object_delete_marker.title() not in ["False", "True"]:
                raise ValueError(
                    "value of ExpiredObjectDeleteMarker must be "
                    "'True' or 'False'",
                )
            return cls(
                date, days, expired_object_delete_marker.lower() == "true",
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            super().toxml(element)
            if self.expired_object_delete_marker is not None:
                SubElement(
                    element,
                    "ExpiredObjectDeleteMarker",
                    str(self.expired_object_delete_marker).lower(),
                )
            return element

    @dataclass(frozen=True)
    class AbortIncompleteMultipartUpload:
        """Abort incomplete multipart upload."""
        days_after_initiation: Optional[int] = None

        @classmethod
        def fromxml(
                cls: Type[LifecycleConfig.AbortIncompleteMultipartUpload],
                element: ET.Element,
        ) -> LifecycleConfig.AbortIncompleteMultipartUpload:
            """Create new object with values from XML element."""
            days_after_initiation = findtext(element, "DaysAfterInitiation")
            return cls(
                days_after_initiation=(
                    int(days_after_initiation) if days_after_initiation
                    else None
                ),
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.days_after_initiation:
                SubElement(
                    element,
                    "DaysAfterInitiation",
                    str(self.days_after_initiation),
                )
            return element

    @dataclass(frozen=True)
    class Rule:
        """Lifecycle rule. """
        status: str
        rule_filter: Optional[Filter] = None
        rule_id: Optional[str] = None
        abort_incomplete_multipart_upload: Optional[
            LifecycleConfig.AbortIncompleteMultipartUpload] = None
        expiration: Optional[LifecycleConfig.Expiration] = None
        noncurrent_version_expiration: Optional[
            LifecycleConfig.NoncurrentVersionExpiration] = None
        noncurrent_version_transition: Optional[
            LifecycleConfig.NoncurrentVersionTransition] = None
        transition: Optional[LifecycleConfig.Transition] = None

        def __post_init__(self):
            Status.check(self.status)
            if self.rule_id is not None:
                object.__setattr__(self, "rule_id", self.rule_id.strip())
                if not self.rule_id:
                    raise ValueError("rule ID must be non-empty string")
                if len(self.rule_id) > 255:
                    raise ValueError("rule ID must not exceed 255 characters")
            if (not self.abort_incomplete_multipart_upload
                and not self.expiration
                and not self.noncurrent_version_expiration
                and not self.noncurrent_version_transition
                    and not self.transition):
                raise ValueError(
                    "at least one of action (AbortIncompleteMultipartUpload, "
                    "Expiration, NoncurrentVersionExpiration, "
                    "NoncurrentVersionTransition or Transition) must be "
                    "specified in a rule")

        @classmethod
        def fromxml(
                cls: Type[LifecycleConfig.Rule],
                element: ET.Element,
        ) -> LifecycleConfig.Rule:
            """Create new object with values from XML element."""
            status = cast(str, findtext(element, "Status", True))
            rule_filter = (
                None if find(element, "Filter") is None
                else Filter.fromxml(cast(ET.Element, find(element, "Filter")))
            )
            rule_id = findtext(element, "ID")
            abort_incomplete_multipart_upload = (
                None if find(element, "AbortIncompleteMultipartUpload") is None
                else LifecycleConfig.AbortIncompleteMultipartUpload.fromxml(
                    cast(
                        ET.Element,
                        find(element, "AbortIncompleteMultipartUpload"),
                    ),
                )
            )
            expiration = (
                None if find(element, "Expiration") is None
                else LifecycleConfig.Expiration.fromxml(
                    cast(ET.Element, find(element, "Expiration")),
                )
            )
            noncurrent_version_expiration = (
                None if find(element, "NoncurrentVersionExpiration") is None
                else
                LifecycleConfig.NoncurrentVersionExpiration.fromxml(
                    cast(
                        ET.Element,
                        find(element, "NoncurrentVersionExpiration"),
                    ),
                )
            )
            noncurrent_version_transition = (
                None if find(element, "NoncurrentVersionTransition") is None
                else
                LifecycleConfig.NoncurrentVersionTransition.fromxml(
                    cast(
                        ET.Element,
                        find(element, "NoncurrentVersionTransition"),
                    ),
                )
            )
            transition = (
                None if find(element, "Transition") is None
                else LifecycleConfig.Transition.fromxml(
                    cast(ET.Element, find(element, "Transition")),
                )
            )

            return cls(
                status=status,
                rule_filter=rule_filter,
                rule_id=rule_id,
                abort_incomplete_multipart_upload=(
                    abort_incomplete_multipart_upload
                ),
                expiration=expiration,
                noncurrent_version_expiration=noncurrent_version_expiration,
                noncurrent_version_transition=noncurrent_version_transition,
                transition=transition,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "Status", self.status)
            if self.rule_filter:
                self.rule_filter.toxml(SubElement(element, "Filter"))
            if self.rule_id is not None:
                SubElement(element, "ID", self.rule_id)
            if self.abort_incomplete_multipart_upload:
                self.abort_incomplete_multipart_upload.toxml(
                    SubElement(element, "AbortIncompleteMultipartUpload"),
                )
            if self.expiration:
                self.expiration.toxml(SubElement(element, "Expiration"))
            if self.noncurrent_version_expiration:
                self.noncurrent_version_expiration.toxml(
                    SubElement(element, "NoncurrentVersionExpiration"),
                )
            if self.noncurrent_version_transition:
                self.noncurrent_version_transition.toxml(
                    SubElement(element, "NoncurrentVersionTransition"),
                )
            if self.transition:
                self.transition.toxml(SubElement(element, "Transition"))
            return element


@dataclass(frozen=True)
class NotificationConfig:
    """Notification configuration."""
    cloud_func_config_list: list[CloudFuncConfig] = field(default_factory=list)
    queue_config_list: list[QueueConfig] = field(default_factory=list)
    topic_config_list: list[TopicConfig] = field(default_factory=list)

    @classmethod
    def fromxml(
            cls: Type[NotificationConfig],
            element: ET.Element,
    ) -> NotificationConfig:
        """Create new object with values from XML element."""
        elements = findall(element, "CloudFunctionConfiguration")
        cloud_func_config_list = [
            NotificationConfig.CloudFuncConfig.fromxml(tag)
            for tag in elements
        ]
        elements = findall(element, "QueueConfiguration")
        queue_config_list = [
            NotificationConfig.QueueConfig.fromxml(tag)
            for tag in elements
        ]
        elements = findall(element, "TopicConfiguration")
        topic_config_list = [
            NotificationConfig.TopicConfig.fromxml(tag)
            for tag in elements
        ]
        return cls(
            cloud_func_config_list, queue_config_list, topic_config_list,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("NotificationConfiguration")
        for cloud_func_config in self.cloud_func_config_list:
            cloud_func_config.toxml(
                SubElement(element, "CloudFunctionConfiguration"),
            )
        for queue_config in self.queue_config_list:
            queue_config.toxml(SubElement(element, "QueueConfiguration"))
        for config in self.topic_config_list:
            config.toxml(SubElement(element, "TopicConfiguration"))
        return element

    @dataclass(frozen=True)
    class FilterRule(ABC):
        """Filter rule."""
        name: str
        value: str

        @classmethod
        def fromxml(
                cls: Type[NotificationConfig.FilterRule],
                element: ET.Element,
        ) -> NotificationConfig.FilterRule:
            """Create new object with values from XML element."""
            name = cast(str, findtext(element, "Name", True))
            value = cast(str, findtext(element, "Value", True))
            return cls(name, value)

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            # element = SubElement(element, "FilterRule")
            SubElement(element, "Name", self.name)
            SubElement(element, "Value", self.value)
            return element

    @dataclass(frozen=True)
    class PrefixFilterRule(FilterRule):
        """Prefix filter rule."""

        def __init__(self, value: str):
            super().__init__(name="prefix", value=value)

    @dataclass(frozen=True)
    class SuffixFilterRule(FilterRule):
        """Suffix filter rule."""

        def __init__(self, value: str):
            super().__init__(name="suffix", value=value)

    @dataclass(frozen=True)
    class CommonConfig(ABC):
        """Common for cloud-function/queue/topic configuration."""
        events: list[str]
        config_id: Optional[str] = None
        prefix_filter_rule: Optional[NotificationConfig.PrefixFilterRule] = None
        suffix_filter_rule: Optional[NotificationConfig.SuffixFilterRule] = None

        def __post_init__(self):
            if not self.events:
                raise ValueError("events must be provided")

        @staticmethod
        def parsexml(
                element: ET.Element,
        ) -> tuple[
            list[str],
            Optional[str],
            Optional[NotificationConfig.PrefixFilterRule],
            Optional[NotificationConfig.SuffixFilterRule],
        ]:
            """Parse XML."""
            elements = findall(element, "Event")
            events = []
            for tag in elements:
                if tag.text is None:
                    raise ValueError("missing value in XML tag 'Event'")
                events.append(tag.text)
            config_id = findtext(element, "Id")
            elem = find(element, "Filter")
            if elem is None:
                return events, config_id, None, None
            prefix_filter_rule = None
            suffix_filter_rule = None
            elem = cast(ET.Element, find(elem, "S3Key", True))
            elements = findall(elem, "FilterRule")
            for tag in elements:
                filter_rule = NotificationConfig.FilterRule.fromxml(tag)
                if filter_rule.name == "prefix":
                    prefix_filter_rule = NotificationConfig.PrefixFilterRule(
                        filter_rule.value,
                    )
                else:
                    suffix_filter_rule = NotificationConfig.SuffixFilterRule(
                        filter_rule.value,
                    )
            return (
                events, config_id, prefix_filter_rule, suffix_filter_rule,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            for event in self.events:
                SubElement(element, "Event", event)
            if self.config_id is not None:
                SubElement(element, "Id", self.config_id)
            if self.prefix_filter_rule or self.suffix_filter_rule:
                rule = SubElement(element, "Filter")
                rule = SubElement(rule, "S3Key")
            if self.prefix_filter_rule:
                self.prefix_filter_rule.toxml(SubElement(rule, "FilterRule"))
            if self.suffix_filter_rule:
                self.suffix_filter_rule.toxml(SubElement(rule, "FilterRule"))
            return element

    @dataclass(frozen=True)
    class CloudFuncConfig(CommonConfig):
        """Cloud function configuration."""
        cloud_func: Optional[str] = None

        def __post_init__(self):
            if not self.cloud_func:
                raise ValueError("cloud function must be provided")

        @classmethod
        def fromxml(
                cls: Type[NotificationConfig.CloudFuncConfig],
                element: ET.Element,
        ) -> NotificationConfig.CloudFuncConfig:
            """Create new object with values from XML element."""
            cloud_func = cast(str, findtext(element, "CloudFunction", True))
            (events, config_id, prefix_filter_rule,
             suffix_filter_rule) = cls.parsexml(element)
            return cls(
                cloud_func=cloud_func,
                events=events,
                config_id=config_id,
                prefix_filter_rule=prefix_filter_rule,
                suffix_filter_rule=suffix_filter_rule,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "CloudFunction", self.cloud_func)
            super().toxml(element)
            return element

    @dataclass(frozen=True)
    class QueueConfig(CommonConfig):
        """Queue configuration."""
        queue: Optional[str] = None

        def __post_init__(self):
            if not self.queue:
                raise ValueError("queue must be provided")

        @classmethod
        def fromxml(
                cls: Type[NotificationConfig.QueueConfig],
                element: ET.Element,
        ) -> NotificationConfig.QueueConfig:
            """Create new object with values from XML element."""
            queue = cast(str, findtext(element, "Queue", True))
            (events, config_id, prefix_filter_rule,
             suffix_filter_rule) = cls.parsexml(element)
            return cls(
                queue=queue,
                events=events,
                config_id=config_id,
                prefix_filter_rule=prefix_filter_rule,
                suffix_filter_rule=suffix_filter_rule,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "Queue", self.queue)
            super().toxml(element)
            return element

    @dataclass(frozen=True)
    class TopicConfig(CommonConfig):
        """Get topic configuration."""
        topic: Optional[str] = None

        def __post_init__(self):
            if not self.topic:
                raise ValueError("topic must be provided")

        @classmethod
        def fromxml(
                cls: Type[NotificationConfig.TopicConfig],
                element: ET.Element,
        ) -> NotificationConfig.TopicConfig:
            """Create new object with values from XML element."""
            topic = cast(str, findtext(element, "Topic", True))
            (events, config_id, prefix_filter_rule,
             suffix_filter_rule) = cls.parsexml(element)
            return cls(
                topic=topic,
                events=events,
                config_id=config_id,
                prefix_filter_rule=prefix_filter_rule,
                suffix_filter_rule=suffix_filter_rule,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "Topic", self.topic)
            super().toxml(element)
            return element


@dataclass(frozen=True)
class ObjectLockConfig:
    """Object lock configuration."""
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"
    DAYS = "Days"
    YEARS = "Years"

    mode: Optional[str]
    duration: Optional[int]
    duration_unit: Optional[str]

    def __post_init__(self):
        if (self.mode is not None) ^ (self.duration is not None):
            if self.mode is None:
                raise ValueError("mode must be provided")
            raise ValueError("duration must be provided")
        if (
                self.mode is not None and self.mode not in [
                    ObjectLockConfig.GOVERNANCE, ObjectLockConfig.COMPLIANCE,
                ]
        ):
            raise ValueError(
                f"mode must be {ObjectLockConfig.GOVERNANCE} or "
                f"{ObjectLockConfig.COMPLIANCE}",
            )
        if (
                self.duration is not None and
                self.duration_unit not in [
                    ObjectLockConfig.DAYS, ObjectLockConfig.YEARS,
                ]
        ):
            raise ValueError(
                f"duration unit must be {ObjectLockConfig.DAYS} or ",
                f"{ObjectLockConfig.YEARS}",
            )
        if self.duration_unit:
            object.__setattr__(
                self, "duration_unit", self.duration_unit.title(),
            )

    @classmethod
    def fromxml(
            cls: Type[ObjectLockConfig],
            element: ET.Element,
    ) -> ObjectLockConfig:
        """Create new object with values from XML element."""
        elem = find(element, "Rule")
        if elem is None:
            return cls(None, None, None)
        elem = cast(ET.Element, find(elem, "DefaultRetention", True))
        mode = findtext(elem, "Mode")
        duration_unit = ObjectLockConfig.DAYS
        duration = findtext(elem, duration_unit)
        if not duration:
            duration_unit = ObjectLockConfig.YEARS
            duration = findtext(elem, duration_unit)
        if not duration:
            raise ValueError(
                f"XML element <{ObjectLockConfig.DAYS}> or "
                f"<{ObjectLockConfig.YEARS}> not found",
            )
        return cls(
            mode=mode,
            duration=int(duration),
            duration_unit=duration_unit,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("ObjectLockConfiguration")
        SubElement(element, "ObjectLockEnabled", "Enabled")
        if self.mode:
            rule = SubElement(element, "Rule")
            retention = SubElement(rule, "DefaultRetention")
            SubElement(retention, "Mode", self.mode)
            if not self.duration_unit:
                raise ValueError("duration unit must be provided")
            SubElement(retention, self.duration_unit, str(self.duration))
        return element


@dataclass(frozen=True)
class ReplicationConfig:
    """Replication configuration."""
    role: str
    rules: list[Rule]

    def __post_init__(self):
        if not self.rules:
            raise ValueError("rules must be provided")
        if len(self.rules) > 1000:
            raise ValueError("more than 1000 rules are not supported")

    @classmethod
    def fromxml(
            cls: Type[ReplicationConfig],
            element: ET.Element,
    ) -> ReplicationConfig:
        """Create new object with values from XML element."""
        role = cast(str, findtext(element, "Role", True))
        rules = [
            ReplicationConfig.Rule.fromxml(tag)
            for tag in findall(element, "Rule")
        ]
        return cls(role, rules)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("ReplicationConfiguration")
        SubElement(element, "Role", self.role)
        for rule in self.rules:
            rule.toxml(SubElement(element, "Rule"))
        return element

    @dataclass(frozen=True)
    class SseKmsEncryptedObjects(Status):
        """SSE KMS encrypted objects."""

    @dataclass(frozen=True)
    class SourceSelectionCriteria:
        """Source selection criteria."""
        sse_kms_encrypted_objects: Optional[
            ReplicationConfig.SseKmsEncryptedObjects] = None

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.SourceSelectionCriteria],
                element: ET.Element,
        ) -> ReplicationConfig.SourceSelectionCriteria:
            """Create new object with values from XML element."""
            return cls(
                sse_kms_encrypted_objects=(
                    None if find(element, "SseKmsEncryptedObjects") is None
                    else ReplicationConfig.SseKmsEncryptedObjects.fromxml(
                        cast(
                            ET.Element,
                            find(element, "SseKmsEncryptedObjects"),
                        ),
                    )
                ),
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.sse_kms_encrypted_objects:
                self.sse_kms_encrypted_objects.toxml(
                    SubElement(element, "SseKmsEncryptedObjects"),
                )
            return element

    @dataclass(frozen=True)
    class ExistingObjectReplication(Status):
        """Existing object replication."""

    @dataclass(frozen=True)
    class DeleteMarkerReplication(Status):
        """Delete marker replication."""

        def __init__(self, status="Disabled"):
            super().__init__(status)

    ReplicationTimeValueT = TypeVar(
        "ReplicationTimeValueT", bound="ReplicationTimeValue",
    )

    @dataclass(frozen=True)
    class ReplicationTimeValue(ABC):
        """Replication time value."""
        minutes: Optional[int] = 15

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.ReplicationTimeValueT],
                element: ET.Element,
        ) -> ReplicationConfig.ReplicationTimeValueT:
            """Create new object with values from XML element."""
            minutes = findtext(element, "Minutes")
            return cls(
                minutes=int(minutes) if minutes else None,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.minutes is not None:
                SubElement(element, "Minutes", str(self.minutes))
            return element

    @dataclass(frozen=True)
    class Time(ReplicationTimeValue):
        """Time."""

    @dataclass(frozen=True)
    class ReplicationTime:
        """Replication time."""
        time: ReplicationConfig.Time
        status: str

        def __post_init__(self,):
            if not self.time:
                raise ValueError("time must be provided")
            Status.check(self.status)

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.ReplicationTime],
                element: ET.Element,
        ) -> ReplicationConfig.ReplicationTime:
            """Create new object with values from XML element."""
            time = ReplicationConfig.Time.fromxml(
                cast(ET.Element, find(element, "Time", strict=True)),
            )
            status = cast(str, findtext(element, "Status", True))
            return cls(time, status)

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            self.time.toxml(SubElement(element, "Time"))
            SubElement(element, "Status", self.status)
            return element

    @dataclass(frozen=True)
    class EventThreshold(ReplicationTimeValue):
        """Event threshold."""

    @dataclass(frozen=True)
    class Metrics:
        """Metrics."""
        event_threshold: ReplicationConfig.EventThreshold
        status: str

        def __post_init__(self):
            if not self.event_threshold:
                raise ValueError("event threshold must be provided")
            Status.check(self.status)

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.Metrics],
                element: ET.Element,
        ) -> ReplicationConfig.Metrics:
            """Create new object with values from XML element."""
            event_threshold = ReplicationConfig.EventThreshold.fromxml(
                cast(ET.Element, find(element, "EventThreshold", True)),
            )
            status = cast(str, findtext(element, "Status", True))
            return cls(event_threshold, status)

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            self.event_threshold.toxml(SubElement(element, "EventThreshold"))
            SubElement(element, "Status", self.status)
            return element

    @dataclass(frozen=True)
    class EncryptionConfig:
        """Encryption configuration."""
        replica_kms_key_id: Optional[str] = None

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.EncryptionConfig],
                element: ET.Element,
        ) -> ReplicationConfig.EncryptionConfig:
            """Create new object with values from XML element."""
            return cls(findtext(element, "ReplicaKmsKeyID"))

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "ReplicaKmsKeyID", self.replica_kms_key_id)
            return element

    @dataclass(frozen=True)
    class AccessControlTranslation:
        """Access control translation."""
        owner: str = "Destination"

        def __post_init__(self):
            if not self.owner:
                raise ValueError("owner must be provided")

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.AccessControlTranslation],
                element: ET.Element,
        ) -> ReplicationConfig.AccessControlTranslation:
            """Create new object with values from XML element."""
            owner = cast(str, findtext(element, "Owner", True))
            return cls(owner)

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "Owner", self.owner)
            return element

    @dataclass(frozen=True)
    class Destination:
        """Replication destination."""
        bucket_arn: str
        access_control_translation: Optional[
            ReplicationConfig.AccessControlTranslation] = None
        account: Optional[str] = None
        encryption_config: Optional[ReplicationConfig.EncryptionConfig] = None
        metrics: Optional[ReplicationConfig.Metrics] = None
        replication_time: Optional[ReplicationConfig.ReplicationTime] = None
        storage_class: Optional[str] = None

        def __post_init__(self):
            if not self.bucket_arn:
                raise ValueError("bucket ARN must be provided")

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.Destination],
                element: ET.Element,
        ) -> ReplicationConfig.Destination:
            """Create new object with values from XML element."""
            access_control_translation = (
                None if find(element, "AccessControlTranslation") is None
                else ReplicationConfig.AccessControlTranslation.fromxml(
                    cast(
                        ET.Element,
                        find(element, "AccessControlTranslation"),
                    ),
                )
            )
            account = findtext(element, "Account")
            bucket_arn = cast(str, findtext(element, "Bucket", True))
            encryption_config = (
                None if find(element, "EncryptionConfiguration") is None
                else ReplicationConfig.EncryptionConfig.fromxml(
                    cast(
                        ET.Element,
                        find(element, "EncryptionConfiguration"),
                    ),
                )
            )
            metrics = (
                None if find(element, "Metrics") is None
                else ReplicationConfig.Metrics.fromxml(
                    cast(ET.Element, find(element, "Metrics")),
                )
            )
            replication_time = (
                None if find(element, "ReplicationTime") is None
                else ReplicationConfig.ReplicationTime.fromxml(
                    cast(ET.Element, find(element, "ReplicationTime")),
                )
            )
            storage_class = findtext(element, "StorageClass")
            return cls(
                bucket_arn, access_control_translation, account,
                encryption_config, metrics, replication_time, storage_class,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.access_control_translation:
                self.access_control_translation.toxml(
                    SubElement(element, "AccessControlTranslation"),
                )
            if self.account is not None:
                SubElement(element, "Account", self.account)
            SubElement(element, "Bucket", self.bucket_arn)
            if self.encryption_config:
                self.encryption_config.toxml(
                    SubElement(element, "EncryptionConfiguration"),
                )
            if self.metrics:
                self.metrics.toxml(SubElement(element, "Metrics"))
            if self.replication_time:
                self.replication_time.toxml(
                    SubElement(element, "ReplicationTime"),
                )
            if self.storage_class:
                SubElement(element, "StorageClass", self.storage_class)
            return element

    @dataclass(frozen=True)
    class Rule:
        """Replication rule. """
        status: str
        rule_id: Optional[str] = None
        rule_filter: Optional[Filter] = None
        destination: Optional[ReplicationConfig.Destination] = None
        delete_marker_replication: Optional[
            ReplicationConfig.DeleteMarkerReplication] = None
        existing_object_replication: Optional[
            ReplicationConfig.ExistingObjectReplication] = None
        prefix: Optional[str] = None
        priority: Optional[int] = None
        source_selection_criteria: Optional[
            ReplicationConfig.SourceSelectionCriteria] = None

        def __post_init__(self):
            Status.check(self.status)
            if self.rule_id is not None:
                object.__setattr__(self, "rule_id", self.rule_id.strip())
                if not self.rule_id:
                    raise ValueError("rule ID must be non-empty string")
                if len(self.rule_id) > 255:
                    raise ValueError("rule ID must not exceed 255 characters")
            if not self.destination:
                raise ValueError("destination must be provided")

        @classmethod
        def fromxml(
                cls: Type[ReplicationConfig.Rule],
                element: ET.Element,
        ) -> ReplicationConfig.Rule:
            """Create new object with values from XML element."""
            status = cast(str, findtext(element, "Status", True))
            rule_id = findtext(element, "ID")
            rule_filter = (
                None if find(element, "Filter") is None
                else Filter.fromxml(cast(ET.Element, find(element, "Filter")))
            )
            destination = (
                None if find(element, "Destination") is None
                else ReplicationConfig.Destination.fromxml(
                    cast(ET.Element, find(element, "Destination")),
                )
            )
            delete_marker_replication = (
                None if find(element, "DeleteMarkerReplication") is None
                else ReplicationConfig.DeleteMarkerReplication.fromxml(
                    cast(
                        ET.Element,
                        find(element, "DeleteMarkerReplication"),
                    ),
                )
            )
            existing_object_replication = (
                None
                if find(element, "ExistingObjectReplication") is None
                else ReplicationConfig.ExistingObjectReplication.fromxml(
                    cast(
                        ET.Element,
                        find(element, "ExistingObjectReplication"),
                    ),
                )
            )
            prefix = findtext(element, "Prefix")
            priority = findtext(element, "Priority")
            source_selection_criteria = (
                None if find(element, "SourceSelectionCriteria") is None
                else ReplicationConfig.SourceSelectionCriteria.fromxml(
                    cast(
                        ET.Element,
                        find(element, "SourceSelectionCriteria"),
                    ),
                )
            )

            return cls(
                status=status,
                rule_id=rule_id,
                rule_filter=rule_filter,
                destination=destination,
                delete_marker_replication=delete_marker_replication,
                existing_object_replication=existing_object_replication,
                prefix=prefix,
                priority=int(priority) if priority else None,
                source_selection_criteria=source_selection_criteria,
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "Status", self.status)
            if self.rule_id is not None:
                SubElement(element, "ID", self.rule_id)
            if self.rule_filter:
                self.rule_filter.toxml(SubElement(element, "Filter"))
            if self.delete_marker_replication:
                self.delete_marker_replication.toxml(
                    SubElement(element, "DeleteMarkerReplication"),
                )
            if self.destination:
                self.destination.toxml(SubElement(element, "Destination"))
            if self.existing_object_replication:
                self.existing_object_replication.toxml(
                    SubElement(element, "ExistingObjectReplication"),
                )
            if self.prefix is not None:
                SubElement(element, "Prefix", self.prefix)
            if self.priority is not None:
                SubElement(element, "Priority", str(self.priority))
            if self.source_selection_criteria:
                self.source_selection_criteria.toxml(
                    SubElement(element, "SourceSelectionCriteria"),
                )
            return element


@dataclass(frozen=True)
class Retention:
    """Retention configuration."""
    COMPLIANCE = "COMPLIANCE"
    GOVERNANCE = "GOVERNANCE"
    mode: str
    retain_until_date: datetime

    def __post_init__(self):
        if self.mode not in [
                Retention.GOVERNANCE, Retention.COMPLIANCE,
        ]:
            raise ValueError(
                f"mode must be {Retention.GOVERNANCE} or "
                f"{Retention.COMPLIANCE}",
            )

    @classmethod
    def fromxml(cls: Type[Retention], element: ET.Element) -> Retention:
        """Create new object with values from XML element."""
        mode = cast(str, findtext(element, "Mode", True))
        retain_until_date = cast(
            datetime,
            from_iso8601utc(
                cast(str, findtext(element, "RetainUntilDate", True)),
            ),
        )
        return cls(mode=mode, retain_until_date=retain_until_date)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("Retention")
        SubElement(element, "Mode", self.mode)
        SubElement(
            element,
            "RetainUntilDate",
            to_iso8601utc(self.retain_until_date),
        )
        return element


@dataclass(frozen=True)
class SSEConfig:
    """server-side encryption configuration."""
    rule: Rule

    def __post_init__(self):
        if not self.rule:
            raise ValueError("rule must be provided")

    @classmethod
    def fromxml(cls: Type[SSEConfig], element: ET.Element) -> SSEConfig:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Rule", True))
        return cls(SSEConfig.Rule.fromxml(element))

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("ServerSideEncryptionConfiguration")
        self.rule.toxml(SubElement(element, "Rule"))
        return element

    @dataclass(frozen=True)
    class Rule(ABC):
        """Server-side encryption rule. """
        AES256 = "AES256"
        AWS_KMS = "aws:kms"
        sse_algorithm: str
        kms_master_key_id: Optional[str] = None

        @classmethod
        def new_sse_s3_rule(cls: Type[SSEConfig.Rule]) -> SSEConfig.Rule:
            """Create SSE-S3 rule."""
            return cls(sse_algorithm=SSEConfig.Rule.AES256)

        @classmethod
        def new_sse_kms_rule(
                cls: Type[SSEConfig.Rule],
                kms_master_key_id: Optional[str] = None,
        ) -> SSEConfig.Rule:
            """Create new SSE-KMS rule."""
            return cls(
                sse_algorithm=SSEConfig.Rule.AWS_KMS,
                kms_master_key_id=kms_master_key_id,
            )

        @classmethod
        def fromxml(
                cls: Type[SSEConfig.Rule],
                element: ET.Element,
        ) -> SSEConfig.Rule:
            """Create new object with values from XML element."""
            element = cast(
                ET.Element,
                find(element, "ApplyServerSideEncryptionByDefault", True),
            )
            return cls(
                sse_algorithm=cast(
                    str, findtext(element, "SSEAlgorithm", True),
                ),
                kms_master_key_id=findtext(element, "KMSMasterKeyID"),
            )

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            tag = SubElement(element, "ApplyServerSideEncryptionByDefault")
            SubElement(tag, "SSEAlgorithm", self.sse_algorithm)
            if self.kms_master_key_id is not None:
                SubElement(tag, "KMSMasterKeyID", self.kms_master_key_id)
            return element


@dataclass(frozen=True)
class Tagging:
    """Tagging for buckets and objects."""
    tags: Optional[Tags]

    @classmethod
    def fromxml(cls: Type[Tagging], element: ET.Element) -> Tagging:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "TagSet", True))
        return cls(
            tags=(
                None if find(element, "Tag") is None
                else Tags.fromxml(element)
            ),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("Tagging")
        if self.tags:
            self.tags.toxml(SubElement(element, "TagSet"))
        return element


@dataclass(frozen=True)
class VersioningConfig:
    """Versioning configuration."""
    DISABLED = "Disabled"
    ENABLED = "Enabled"
    OFF = "Off"
    SUSPENDED = "Suspended"

    status: Optional[str] = None
    mfa_delete: Optional[str] = None
    excluded_prefixes: Optional[list[str]] = None
    exclude_folders: bool = False

    def __post_init__(self):
        if (
                self.status is not None and
                self.status not in [
                    VersioningConfig.ENABLED, VersioningConfig.SUSPENDED,
                ]
        ):
            raise ValueError(
                f"status must be {VersioningConfig.ENABLED} or "
                f"{VersioningConfig.SUSPENDED}",
            )
        if (
                self.mfa_delete is not None and
                self.mfa_delete not in [
                    VersioningConfig.ENABLED, VersioningConfig.DISABLED,
                ]
        ):
            raise ValueError(
                f"MFA delete must be {VersioningConfig.ENABLED} or "
                f"{VersioningConfig.DISABLED}",
            )

    @property
    def status_string(self) -> str:
        """Convert status to status string. """
        return self.status or VersioningConfig.OFF

    @classmethod
    def fromxml(
            cls: Type[VersioningConfig],
            element: ET.Element,
    ) -> VersioningConfig:
        """Create new object with values from XML element."""
        status = findtext(element, "Status")
        mfa_delete = findtext(element, "MFADelete")
        excluded_prefixes = [
            prefix.text
            for prefix in findall(
                element,
                "ExcludedPrefixes/Prefix",
            )
        ]
        exclude_folders = cast(
            str,
            findtext(element, "ExcludeFolders", default=""),
        ).lower() == "true"
        return cls(
            status=status,
            mfa_delete=mfa_delete,
            excluded_prefixes=cast(Union[List[str], None], excluded_prefixes),
            exclude_folders=exclude_folders,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("VersioningConfiguration")
        if self.status:
            SubElement(element, "Status", self.status)
        if self.mfa_delete:
            SubElement(element, "MFADelete", self.mfa_delete)
        for prefix in self.excluded_prefixes or []:
            SubElement(
                SubElement(element, "ExcludedPrefixes"),
                "Prefix",
                prefix,
            )
        if self.exclude_folders:
            SubElement(element, "ExcludeFolders", "true")
        return element


################################################################################
###########                API request only XML models               ###########
################################################################################

@dataclass(frozen=True)
class CreateBucketConfiguration:
    """CreateBucket configuration."""
    location_constraint: str
    location: Optional[CreateBucketConfiguration.Location] = None
    bucket: Optional[CreateBucketConfiguration.Bucket] = None
    tags: Optional[Tags] = None

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("CreateBucketConfiguration")
        SubElement(element, "LocationConstraint", self.location_constraint)
        if self.location:
            self.location.toxml(SubElement(element, "Location"))
        if self.bucket:
            self.bucket.toxml(SubElement(element, "Bucket"))
        if self.tags:
            self.tags.toxml(SubElement(element, "Tags"))
        return element

    @dataclass(frozen=True)
    class Location:
        """Bucket location information of CreateBucketConfiguration."""
        name: Optional[str] = None
        type: Optional[str] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.name or self.type:
                element = SubElement(element, "Location")
            if self.name:
                SubElement(element, "Name", self.name)
            if self.type:
                SubElement(element, "Type", self.type)
            return element

    @dataclass(frozen=True)
    class Bucket:
        """Bucket properties of CreateBucketConfiguration."""
        data_redundancy: Optional[str] = None
        type: Optional[str] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.data_redundancy or self.type:
                element = SubElement(element, "Bucket")
            if self.data_redundancy:
                SubElement(element, "DataRedundancy", self.data_redundancy)
            if self.type:
                SubElement(element, "Type", self.type)
            return element


@dataclass(frozen=True)
class DeleteRequest:
    """Delete object request."""

    objects: list[DeleteRequest.Object]
    quiet: bool = False

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("Delete")
        if self.quiet:
            SubElement(element, "Quiet", "true")
        for obj in self.objects:
            obj.toxml(SubElement(element, "Object"))
        return element

    @dataclass(frozen=True)
    class Object:
        """Delete object request information."""

        name: str
        version_id: Optional[str] = None
        etag: Optional[str] = None
        last_modified_time: Optional[datetime] = None
        size: Optional[int] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            SubElement(element, "Key", self.name)
            if self.version_id is not None:
                SubElement(element, "VersionId", self.version_id)
            if self.etag:
                SubElement(element, "ETag", self.etag)
            if self.last_modified_time:
                SubElement(
                    element,
                    "LastModifiedTime", to_http_header(
                        self.last_modified_time),
                )
            if self.size is not None:
                SubElement(element, "Size", str(self.size))
            return element


class PostPolicy:
    """
    Post policy information to be used to generate presigned post policy
    form-data. Condition elements and respective condition for Post policy
    is available at
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html#sigv4-PolicyConditions
    """
    _RESERVED_ELEMENTS = (
        "bucket",
        "x-amz-algorithm",
        "x-amz-credential",
        "x-amz-date",
        "policy",
        "x-amz-signature",
    )
    _EQ = "eq"
    _STARTS_WITH = "starts-with"
    _ALGORITHM = "AWS4-HMAC-SHA256"

    @staticmethod
    def _trim_dollar(value: str) -> str:
        """Trim dollar character if present."""
        return value[1:] if value.startswith("$") else value

    def __init__(self, bucket_name: str, expiration: datetime):
        check_bucket_name(bucket_name)
        self._bucket_name = bucket_name
        self._expiration = expiration
        self._conditions: OrderedDict = OrderedDict()
        self._conditions[self._EQ] = OrderedDict()
        self._conditions[self._STARTS_WITH] = OrderedDict()
        self._lower_limit: Optional[int] = None
        self._upper_limit: Optional[int] = None

    def add_equals_condition(self, element: str, value: str):
        """Add equals condition of an element and value."""
        if not element:
            raise ValueError("condition element cannot be empty")
        element = self._trim_dollar(element)
        if (
                element in [
                    "success_action_redirect",
                    "redirect",
                    "content-length-range",
                ]
        ):
            raise ValueError(element + " is unsupported for equals condition")
        if element in self._RESERVED_ELEMENTS:
            raise ValueError(element + " cannot be set")
        self._conditions[self._EQ][element] = value

    def remove_equals_condition(self, element: str):
        """Remove previously set equals condition of an element."""
        if not element:
            raise ValueError("condition element cannot be empty")
        self._conditions[self._EQ].pop(element)

    def add_starts_with_condition(self, element: str, value: str):
        """
        Add starts-with condition of an element and value. Value set to empty
        string does matching any content condition.
        """
        if not element:
            raise ValueError("condition element cannot be empty")
        element = self._trim_dollar(element)
        if (
                element in ["success_action_status", "content-length-range"] or
                (
                    element.startswith("x-amz-") and
                    not element.startswith("x-amz-meta-")
                )
        ):
            raise ValueError(
                f"{element} is unsupported for starts-with condition",
            )
        if element in self._RESERVED_ELEMENTS:
            raise ValueError(element + " cannot be set")
        self._conditions[self._STARTS_WITH][element] = value

    def remove_starts_with_condition(self, element: str):
        """Remove previously set starts-with condition of an element."""
        if not element:
            raise ValueError("condition element cannot be empty")
        self._conditions[self._STARTS_WITH].pop(element)

    def add_content_length_range_condition(  # pylint: disable=invalid-name
            self, lower_limit: int, upper_limit: int):
        """Add content-length-range condition with lower and upper limits."""
        if lower_limit < 0:
            raise ValueError("lower limit cannot be negative number")
        if upper_limit < 0:
            raise ValueError("upper limit cannot be negative number")
        if lower_limit > upper_limit:
            raise ValueError("lower limit cannot be greater than upper limit")
        self._lower_limit = lower_limit
        self._upper_limit = upper_limit

    def remove_content_length_range_condition(  # pylint: disable=invalid-name
            self):
        """Remove previously set content-length-range condition."""
        self._lower_limit = None
        self._upper_limit = None

    def form_data(self, creds: Credentials, region: str):
        """
        Return form-data of this post policy. The returned dict contains
        x-amz-algorithm, x-amz-credential, x-amz-security-token, x-amz-date,
        policy and x-amz-signature.
        """
        if not region:
            raise ValueError("region must be provided")
        if (
                "key" not in self._conditions[self._EQ] and
                "key" not in self._conditions[self._STARTS_WITH]
        ):
            raise ValueError("key condition must be set")

        policy: OrderedDict = OrderedDict()
        policy["expiration"] = to_iso8601utc(self._expiration)
        policy["conditions"] = [[self._EQ, "$bucket", self._bucket_name]]
        for cond_key, conditions in self._conditions.items():
            for key, value in conditions.items():
                policy["conditions"].append([cond_key, "$"+key, value])
        if self._lower_limit is not None and self._upper_limit is not None:
            policy["conditions"].append(
                ["content-length-range", self._lower_limit, self._upper_limit],
            )
        utcnow = datetime.utcnow()
        credential = get_credential_string(creds.access_key, utcnow, region)
        amz_date = to_amz_date(utcnow)
        policy["conditions"].append(
            [self._EQ, "$x-amz-algorithm", self._ALGORITHM],
        )
        policy["conditions"].append(
            [self._EQ, "$x-amz-credential", credential])
        if creds.session_token:
            policy["conditions"].append(
                [self._EQ, "$x-amz-security-token", creds.session_token],
            )
        policy["conditions"].append([self._EQ, "$x-amz-date", amz_date])

        policy_encoded = base64.b64encode(
            json.dumps(policy).encode(),
        ).decode("utf-8")
        signature = post_presign_v4(
            policy_encoded, creds.secret_key, utcnow, region,
        )
        form_data = {
            "x-amz-algorithm": self._ALGORITHM,
            "x-amz-credential": credential,
            "x-amz-date": amz_date,
            "policy": policy_encoded,
            "x-amz-signature": signature,
        }
        if creds.session_token:
            form_data["x-amz-security-token"] = creds.session_token
        return form_data

    @property
    def bucket_name(self) -> str:
        """Get bucket name."""
        return self._bucket_name


@dataclass(frozen=True)
class SelectObjectContentRequest:
    """Select object content request."""

    expression: str
    input_serialization: InputSerialization
    output_serialization: OutputSerialization
    request_progress: bool = False
    scan_start_range: Optional[int] = None
    scan_end_range: Optional[int] = None

    def __post_init__(self):
        if not self.expression:
            raise ValueError("SQL expression must be provided")

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("SelectObjectContentRequest")
        SubElement(element, "Expression", self.expression)
        SubElement(element, "ExpressionType", "SQL")
        self.input_serialization.toxml(
            SubElement(element, "InputSerialization"),
        )
        self.output_serialization.toxml(
            SubElement(element, "OutputSerialization"),
        )
        if self.request_progress:
            SubElement(
                SubElement(element, "RequestProgress"), "Enabled", "true",
            )
        if self.scan_start_range or self.scan_end_range:
            tag = SubElement(element, "ScanRange")
            if self.scan_start_range:
                SubElement(tag, "Start", str(self.scan_start_range))
            if self.scan_end_range:
                SubElement(tag, "End", str(self.scan_end_range))
        return element

    @dataclass(frozen=True)
    class InputSerialization(ABC):
        """Input serialization."""
        compression_type: Optional[
            SelectObjectContentRequest.CompressionType] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            if self.compression_type is not None:
                SubElement(
                    element,
                    "CompressionType",
                    str(self.compression_type),
                )
            return element

    @dataclass(frozen=True)
    class CSVInputSerialization(InputSerialization):
        """CSV input serialization."""
        allow_quoted_record_delimiter: Optional[str] = None
        comments: Optional[str] = None
        field_delimiter: Optional[str] = None
        file_header_info: Optional[
            SelectObjectContentRequest.FileHeaderInfo
        ] = None
        quote_character: Optional[str] = None
        quote_escape_character: Optional[str] = None
        record_delimiter: Optional[str] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            super().toxml(element)
            element = SubElement(element, "CSV")
            if self.allow_quoted_record_delimiter is not None:
                SubElement(
                    element,
                    "AllowQuotedRecordDelimiter",
                    self.allow_quoted_record_delimiter,
                )
            if self.comments is not None:
                SubElement(element, "Comments", self.comments)
            if self.field_delimiter is not None:
                SubElement(element, "FieldDelimiter", self.field_delimiter)
            if self.file_header_info is not None:
                SubElement(
                    element,
                    "FileHeaderInfo",
                    str(self.file_header_info),
                )
            if self.quote_character is not None:
                SubElement(element, "QuoteCharacter", self.quote_character)
            if self.quote_escape_character is not None:
                SubElement(
                    element,
                    "QuoteEscapeCharacter",
                    self.quote_escape_character,
                )
            if self.record_delimiter is not None:
                SubElement(
                    element,
                    "RecordDelimiter",
                    self.record_delimiter,
                )
            return element

    @dataclass(frozen=True)
    class JSONInputSerialization(InputSerialization):
        """JSON input serialization."""
        json_type: Optional[
            SelectObjectContentRequest.JsonType] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            super().toxml(element)
            element = SubElement(element, "JSON")
            if self.json_type is not None:
                SubElement(element, "Type", str(self.json_type))
            return element

    @dataclass(frozen=True)
    class ParquetInputSerialization(InputSerialization):
        """Parquet input serialization."""

        def toxml(  # pylint: disable=no-self-use
                self,
                element: Optional[ET.Element],
        ) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            super().toxml(element)
            SubElement(element, "Parquet")
            return element

    class CompressionType(str, Enum):
        """Compression format of CSV and JSON input serialization."""
        NONE = "NONE"
        GZIP = "GZIP"
        BZIP2 = "BZIP2"

    class FileHeaderInfo(str, Enum):
        """First line description of CSV object."""
        USE = "USE"
        IGNORE = "IGNORE"
        NONE = "NONE"

    class JsonType(str, Enum):
        """JSON object type."""
        DOCUMENT = "DOCUMENT"
        LINES = "LINES"

    @dataclass(frozen=True)
    class OutputSerialization(ABC):
        """Output serialization."""

        def toxml(  # pylint: disable=no-self-use
                self,
                element: Optional[ET.Element],
        ) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            return element

    @dataclass(frozen=True)
    class CSVOutputSerialization(OutputSerialization):
        """CSV output serialization."""
        field_delimiter: Optional[str] = None
        quote_character: Optional[str] = None
        quote_escape_character: Optional[str] = None
        quote_fields: Optional[
            SelectObjectContentRequest.QuoteFields
        ] = None
        record_delimiter: Optional[str] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            element = SubElement(element, "CSV")
            if self.field_delimiter is not None:
                SubElement(element, "FieldDelimiter", self.field_delimiter)
            if self.quote_character is not None:
                SubElement(element, "QuoteCharacter", self.quote_character)
            if self.quote_escape_character is not None:
                SubElement(
                    element,
                    "QuoteEscapeCharacter",
                    self.quote_escape_character,
                )
            if self.quote_fields is not None:
                SubElement(element, "QuoteFields", str(self.quote_fields))
            if self.record_delimiter is not None:
                SubElement(
                    element,
                    "RecordDelimiter",
                    self.record_delimiter,
                )
            return element

    @dataclass(frozen=True)
    class JSONOutputSerialization(OutputSerialization):
        """JSON output serialization."""
        record_delimiter: Optional[str] = None

        def toxml(self, element: Optional[ET.Element]) -> ET.Element:
            """Convert to XML."""
            if element is None:
                raise ValueError("element must be provided")
            element = SubElement(element, "JSON")
            if self.record_delimiter is not None:
                SubElement(
                    element,
                    "RecordDelimiter",
                    self.record_delimiter,
                )
            return element

    class QuoteFields(str, Enum):
        """Quotation field type."""
        ALWAYS = "ALWAYS"
        ASNEEDED = "ASNEEDED"


################################################################################
###########                API response only XML models              ###########
################################################################################

@dataclass(frozen=True)
class AccessControlPolicy:
    """Access control policy of ACL."""
    _AUTHENTICATED_USERS_URL = (
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    )
    _ALL_USERS_URL = "http://acs.amazonaws.com/groups/global/AllUsers"
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    access_control_list: Optional[AccessControlList] = None

    @classmethod
    def fromxml(
            cls: Type[AccessControlPolicy],
            element: ET.Element,
    ) -> AccessControlPolicy:
        """Create new object with values from XML element."""
        elem = find(element, "Owner")
        owner_id, owner_name = (
            (None, None) if elem is None
            else (findtext(elem, "ID"), findtext(elem, "DisplayName"))
        )
        access_control_list = (
            None if find(element, "AccessControlList") is None
            else AccessControlPolicy.AccessControlList.fromxml(
                cast(ET.Element, find(element, "AccessControlList")),
            )
        )
        return cls(
            owner_id=owner_id,
            owner_name=owner_name,
            access_control_list=access_control_list,
        )

    @property
    def canned_acl(self) -> str:
        """Get canned ACL."""
        if not self.access_control_list:
            return ""
        if not self.access_control_list.grants:
            return ""
        grant_len = len(self.access_control_list.grants)
        if grant_len < 1 or grant_len > 3:
            return ""
        for grant in self.access_control_list.grants:
            if not grant or not grant.grantee:
                continue
            if (
                    grant.permission ==
                    AccessControlPolicy.Permission.FULL_CONTROL and
                    len(self.access_control_list.grants) == 1 and
                    not grant.grantee.uri
            ):
                return "private"
            if (
                    grant.permission == AccessControlPolicy.Permission.READ and
                    len(self.access_control_list.grants) == 2
            ):
                if grant.grantee.uri == self._AUTHENTICATED_USERS_URL:
                    return "authenticated-read"
                if grant.grantee.uri == self._ALL_USERS_URL:
                    return "public-read"
                if self.owner_id == grant.grantee.grantee_id:
                    return "bucket-owner-read"
            elif (
                    grant.permission == AccessControlPolicy.Permission.WRITE and
                    len(self.access_control_list.grants) == 3 and
                    grant.grantee.uri == self._ALL_USERS_URL
            ):
                return "public-read-write"
        return ""

    @property
    def grant_acl(self) -> Optional[dict[str, str]]:
        """Get grant ACLs."""
        if not self.access_control_list or not self.access_control_list.grants:
            return None
        mapping = {
            AccessControlPolicy.Permission.READ: "X-Amz-Grant-Read",
            AccessControlPolicy.Permission.WRITE: "X-Amz-Grant-Write",
            AccessControlPolicy.Permission.READ_ACP: "X-Amz-Grant-Read-Acp",
            AccessControlPolicy.Permission.WRITE_ACP: "X-Amz-Grant-Write-Acp",
            AccessControlPolicy.Permission.FULL_CONTROL:
            "X-Amz-Grant-Full-Control",
        }
        acls: dict[str, str] = {}
        for grant in self.access_control_list.grants:
            if (
                    not grant or
                    not grant.permission or
                    not grant.grantee or
                    not grant.grantee.grantee_id
            ):
                continue
            value = mapping.get(grant.permission)
            if value:
                acls[value] = "id=" + grant.grantee.grantee_id
        return acls

    @dataclass(frozen=True)
    class AccessControlList:
        """Access control list"""
        grants: Optional[List[AccessControlPolicy.Grant]] = None

        @classmethod
        def fromxml(
                cls: Type[AccessControlPolicy.AccessControlList],
                element: ET.Element,
        ) -> AccessControlPolicy.AccessControlList:
            """Create new object with values from XML element."""
            return cls(
                grants=[
                    AccessControlPolicy.Grant.fromxml(elem)
                    for elem in findall(element, "Grant")
                ],
            )

    @dataclass(frozen=True)
    class Grant:
        """Grant."""
        grantee: Optional[AccessControlPolicy.Grantee] = None
        permission: Optional[AccessControlPolicy.Permission] = None

        @classmethod
        def fromxml(
                cls: Type[AccessControlPolicy.Grant],
                element: ET.Element,
        ) -> AccessControlPolicy.Grant:
            """Create new object with values from XML element."""
            permission = findtext(element, "Permission")
            return cls(
                grantee=(
                    None if find(element, "Grantee") is None
                    else AccessControlPolicy.Grantee.fromxml(
                        cast(ET.Element, find(element, "Grantee")),
                    )
                ),
                permission=(
                    AccessControlPolicy.Permission(permission) if permission
                    else None
                ),
            )

    @dataclass(frozen=True)
    class Grantee:
        """Grantee."""
        display_name: Optional[str] = None
        email_address: Optional[str] = None
        grantee_id: Optional[str] = None
        grantee_type: Optional[AccessControlPolicy.GranteeType] = None
        uri: Optional[str] = None

        @classmethod
        def fromxml(
                cls: Type[AccessControlPolicy.Grantee],
                element: ET.Element,
        ) -> AccessControlPolicy.Grantee:
            """Create new object with values from XML element."""
            grantee_type = findtext(element, "Type")
            return cls(
                display_name=findtext(element, "DisplayName"),
                email_address=findtext(element, "EmailAddress"),
                grantee_id=findtext(element, "ID"),
                grantee_type=(
                    AccessControlPolicy.GranteeType(grantee_type)
                    if grantee_type else None
                ),
                uri=findtext(element, "URI"),
            )

    class GranteeType(str, Enum):
        """Grantee type."""
        CanonicalUser = "CanonicalUser"
        AmazonCustomerByEmail = "AmazonCustomerByEmail"
        Group = "Group"

    class Permission(str, Enum):
        """Grant permission."""
        FULL_CONTROL = "FULL_CONTROL"
        WRITE = "WRITE"
        WRITE_ACP = "WRITE_ACP"
        READ = "READ"
        READ_ACP = "READ_ACP"


@dataclass(frozen=True)
class BasePartsResult(ABC):
    """
    Base part information for `ListPartsResult` and
    `GetObjectAttributesOutput.ObjectParts`.
    """
    is_truncated: bool = False
    max_parts: Optional[int] = None
    next_part_number_marker: Optional[int] = None
    part_number_marker: Optional[int] = None
    parts: Optional[List[Part]] = None

    @classmethod
    def parsexml(
            cls: Type[BasePartsResult],
            element: ET.Element,
    ) -> Tuple[bool, Optional[int], Optional[int], Optional[int], List[Part]]:
        """Create new object with values from XML element."""
        max_parts = findtext(element, "MaxParts")
        next_part_number_marker = findtext(element, "NextPartNumberMarker")
        part_number_marker = findtext(element, "PartNumberMarker")
        return (
            cast(
                str,
                findtext(element, "IsTruncated", default=""),
            ).lower() == "true",
            int(max_parts) if max_parts else None,
            int(next_part_number_marker) if next_part_number_marker else None,
            int(part_number_marker) if part_number_marker else None,
            [Part.fromxml(elem) for elem in findall(element, "Part")],
        )


@dataclass(frozen=True)
class CompleteMultipartUploadResult(Checksum):
    """CompleteMultipartUpload API result."""
    bucket_name: Optional[str] = None
    object_name: Optional[str] = None
    location: Optional[str] = None
    etag: Optional[str] = None
    version_id: Optional[str] = None

    @classmethod
    def new(
            cls: Type[CompleteMultipartUploadResult],
            response: HTTPResponse,
    ) -> CompleteMultipartUploadResult:
        """Create CompleteMultipartUploadResult from response data."""
        element = ET.fromstring(response.data.decode())
        checksum = Checksum.fromxml(element)
        return CompleteMultipartUploadResult(
            bucket_name=findtext(element, "Bucket"),
            object_name=findtext(element, "Key"),
            location=findtext(element, "Location"),
            etag=cast(
                str, findtext(element, "ETag", default="")).replace('"', ""),
            version_id=response.headers.get("x-amz-version-id"),
            **vars(checksum),
        )


@dataclass(frozen=True)
class CopyObjectResult(Checksum):
    """CopyObject result."""
    etag: str = ""
    last_modified: Optional[datetime] = None

    @classmethod
    def fromxml(
            cls: Type[CopyObjectResult],
            element: ET.Element,
    ) -> CopyObjectResult:
        """Create new object with values from XML element."""
        etag = cast(str, findtext(element, "ETag", True)).replace('"', "")
        value = findtext(element, "LastModified")
        last_modified = from_iso8601utc(value) if value else None
        checksum = Checksum.fromxml(element)
        return cls(
            etag=etag,
            last_modified=last_modified,
            **vars(checksum),
        )


CopyPartResult = CopyObjectResult


@dataclass(frozen=True)
class DeleteResult:
    """Delete object result."""
    objects: list[Deleted] = field(default_factory=list)
    errors: list[Error] = field(default_factory=list)

    @classmethod
    def fromxml(cls: Type[DeleteResult], element: ET.Element) -> DeleteResult:
        """Create new object with values from XML element."""
        elements = findall(element, "Deleted")
        objects = []
        for tag in elements:
            objects.append(DeleteResult.Deleted.fromxml(tag))
        elements = findall(element, "Error")
        errors = []
        for tag in elements:
            errors.append(DeleteResult.Error.fromxml(tag))
        return cls(objects=objects, errors=errors)

    @dataclass(frozen=True)
    class Deleted:
        """Deleted object information."""
        name: str
        version_id: Optional[str]
        delete_marker: bool
        delete_marker_version_id: Optional[str]

        @classmethod
        def fromxml(
                cls: Type[DeleteResult.Deleted],
                element: ET.Element,
        ) -> DeleteResult.Deleted:
            """Create new object with values from XML element."""
            name = cast(str, findtext(element, "Key", True))
            version_id = findtext(element, "VersionId")
            delete_marker = cast(str, findtext(
                element, "DeleteMarker", default=""))
            delete_marker_version_id = findtext(
                element, "DeleteMarkerVersionId",
            )
            return cls(
                name=name,
                version_id=version_id,
                delete_marker=delete_marker.lower() == "true",
                delete_marker_version_id=delete_marker_version_id,
            )

    @dataclass(frozen=True)
    class Error:
        """Delete error information."""
        code: str
        message: Optional[str]
        name: Optional[str]
        version_id: Optional[str]

        @classmethod
        def fromxml(
                cls: Type[DeleteResult.Error],
                element: ET.Element,
        ) -> DeleteResult.Error:
            """Create new object with values from XML element."""
            code = cast(str, findtext(element, "Code", True))
            message = findtext(element, "Message")
            name = findtext(element, "Key")
            version_id = findtext(element, "VersionId")
            return cls(
                code=code,
                message=message,
                name=name,
                version_id=version_id,
            )


@dataclass(frozen=True)
class GetObjectAttributesOutput:
    """Object attributes."""
    etag: Optional[str] = None
    checksum: Optional[Checksum] = None
    object_parts: Optional[ObjectParts] = None
    storage_class: Optional[str] = None
    object_size: Optional[int] = None

    @classmethod
    def fromxml(
            cls: Type[GetObjectAttributesOutput],
            element: ET.Element,
    ) -> GetObjectAttributesOutput:
        """Create new object with values from XML element."""
        object_size = findtext(element, "ObjectSize")
        return cls(
            etag=findtext(element, "ETag"),
            checksum=(
                None if find(element, "Checksum") is None
                else Checksum.fromxml(
                    cast(ET.Element, find(element, "Checksum")),
                )
            ),
            object_parts=(
                None if find(element, "ObjectParts") is None
                else GetObjectAttributesOutput.ObjectParts.fromxml(
                    cast(ET.Element, find(element, "ObjectParts")),
                )
            ),
            storage_class=findtext(element, "StorageClass"),
            object_size=int(object_size) if object_size else None,
        )

    @dataclass(frozen=True)
    class ObjectParts(BasePartsResult):
        """Object parts."""
        parts_count: Optional[int] = None

        @classmethod
        def fromxml(
                cls: Type[GetObjectAttributesOutput.ObjectParts],
                element: ET.Element,
        ) -> GetObjectAttributesOutput.ObjectParts:
            """Create new object with values from XML element."""
            (
                is_truncated,
                max_parts,
                next_part_number_marker,
                part_number_marker,
                parts,
            ) = super().parsexml(element)
            parts_count = findtext(element, "PartsCount")
            return cls(
                part_number_marker=part_number_marker,
                next_part_number_marker=next_part_number_marker,
                max_parts=max_parts,
                is_truncated=is_truncated,
                parts=parts,
                parts_count=int(parts_count) if parts_count else None,
            )


@dataclass(frozen=True)
class ListAllMyBucketsResult:
    """LissBuckets API result."""
    buckets: list[Bucket] = field(default_factory=list)
    prefix: Optional[str] = None
    continuation_token: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None

    @classmethod
    def fromxml(
            cls: Type[ListAllMyBucketsResult],
            element: ET.Element,
    ) -> ListAllMyBucketsResult:
        """Create new object with values from XML element."""
        prefix = findtext(element, "Prefix")
        continuation_token = findtext(element, "ContinuationToken")
        owner = find(element, "Owner")
        owner_id = None if owner is None else findtext(owner, "ID")
        owner_name = None if owner is None else findtext(owner, "DisplayName")
        element = cast(ET.Element, find(element, "Buckets", True))
        buckets = [
            ListAllMyBucketsResult.Bucket.fromxml(tag)
            for tag in findall(element, "Bucket")
        ]
        return cls(
            buckets=buckets,
            prefix=prefix,
            continuation_token=continuation_token,
            owner_id=owner_id,
            owner_name=owner_name,
        )

    @dataclass(frozen=True)
    class Bucket:
        """Bucket information."""
        name: str
        creation_date: Optional[datetime] = None
        bucket_region: Optional[str] = None
        bucket_arn: Optional[str] = None

        @classmethod
        def fromxml(
                cls: Type[ListAllMyBucketsResult.Bucket],
                element: ET.Element,
        ) -> ListAllMyBucketsResult.Bucket:
            """Create new object with values from XML element."""
            name = cast(str, findtext(element, "Name", True))
            creation_date = findtext(element, "CreationDate")
            return cls(
                name=name,
                creation_date=from_iso8601utc(
                    creation_date) if creation_date else None,
                bucket_region=findtext(element, "BucketRegion"),
                bucket_arn=findtext(element, "BucketArn"),
            )


@dataclass(frozen=True)
class InitiateMultipartUploadResult:
    """CreateMultipartUpload result."""
    bucket_name: str
    object_name: str
    upload_id: str

    @classmethod
    def fromxml(
            cls: Type[InitiateMultipartUploadResult],
            element: ET.Element,
    ) -> InitiateMultipartUploadResult:
        """Create new object with values from XML element."""
        return cls(
            bucket_name=cast(str, findtext(element, "Bucket", True)),
            object_name=cast(str, findtext(element, "Key", True)),
            upload_id=cast(str, findtext(element, "UploadId", True)),
        )


@dataclass(frozen=True)
class ListMultipartUploadsResult:
    """ListMultipartUploads API result."""
    encoding_type: Optional[str] = None
    bucket_name: Optional[str] = None
    key_marker: Optional[str] = None
    upload_id_marker: Optional[str] = None
    next_key_marker: Optional[str] = None
    next_upload_id_marker: Optional[str] = None
    max_uploads: Optional[int] = None
    is_truncated: bool = False
    uploads: list[Upload] = field(default_factory=list)

    @classmethod
    def fromxml(
            cls: Type[ListMultipartUploadsResult],
            element: ET.Element,
    ) -> ListMultipartUploadsResult:
        """Create new object with values from XML element."""
        encoding_type = findtext(element, "EncodingType")
        key_marker = findtext(element, "KeyMarker")
        if key_marker is not None and encoding_type == "url":
            key_marker = unquote_plus(key_marker)
        next_key_marker = findtext(element, "NextKeyMarker")
        if next_key_marker is not None and encoding_type == "url":
            next_key_marker = unquote_plus(next_key_marker)
        max_uploads = findtext(element, "MaxUploads")

        return ListMultipartUploadsResult(
            encoding_type=encoding_type,
            bucket_name=findtext(element, "Bucket"),
            key_marker=key_marker,
            upload_id_marker=findtext(element, "UploadIdMarker"),
            next_key_marker=next_key_marker,
            next_upload_id_marker=findtext(element, "NextUploadIdMarker"),
            max_uploads=int(max_uploads) if max_uploads else None,
            is_truncated=cast(
                str,
                findtext(element, "IsTruncated", default=""),
            ).lower() == "true",
            uploads=[
                ListMultipartUploadsResult.Upload(tag, encoding_type)
                for tag in findall(element, "Upload")
            ],
        )

    @dataclass(frozen=True)
    class Upload:
        """ Upload information of a multipart upload."""
        object_name: str
        encoding_type: Optional[str] = None
        upload_id: Optional[str] = None
        initiator_id: Optional[str] = None
        initiator_name: Optional[str] = None
        owner_id: Optional[str] = None
        owner_name: Optional[str] = None
        storage_class: Optional[str] = None
        initiated_time: Optional[datetime] = None
        checksum_algorithm: Optional[str] = None
        checksum_type: Optional[str] = None

        def __init__(
                self, element: ET.Element, encoding_type: Optional[str] = None,
        ):
            object_name = cast(str, findtext(element, "Key", True))
            object.__setattr__(
                self,
                "object_name",
                unquote_plus(object_name) if encoding_type == "url"
                else object_name,
            )
            object.__setattr__(self, "encoding_type", encoding_type)
            object.__setattr__(self, "upload_id",
                               findtext(element, "UploadId"))
            tag = find(element, "Initiator")
            object.__setattr__(
                self,
                "initiator_id",
                None if tag is None else findtext(tag, "ID"),
            )
            object.__setattr__(
                self,
                "initiator_name",
                None if tag is None else findtext(tag, "DisplayName"),
            )
            tag = find(element, "Owner")
            object.__setattr__(
                self,
                "owner_id",
                None if tag is None else findtext(tag, "ID"),
            )
            object.__setattr__(
                self,
                "owner_name",
                None if tag is None else findtext(tag, "DisplayName"),
            )
            object.__setattr__(
                self,
                "storage_class",
                findtext(element, "StorageClass"),
            )
            initiated_time = findtext(element, "Initiated")
            object.__setattr__(
                self,
                "initiated_time",
                from_iso8601utc(initiated_time) if initiated_time else None,
            )
            object.__setattr__(
                self,
                "checksum_algorithm",
                findtext(element, "ChecksumAlgorithm"),
            )
            object.__setattr__(
                self,
                "checksum_type",
                findtext(element, "ChecksumType"),
            )


@dataclass(frozen=True)
class ListPartsResult(BasePartsResult):
    """ListParts API result."""
    bucket_name: Optional[str] = None
    object_name: Optional[str] = None
    initiator_id: Optional[str] = None
    initiator_name: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    storage_class: Optional[str] = None

    @classmethod
    def fromxml(
            cls: Type[ListPartsResult],
            element: ET.Element,
    ) -> ListPartsResult:
        """Create new object with values from XML element."""
        (
            is_truncated,
            max_parts,
            next_part_number_marker,
            part_number_marker,
            parts,
        ) = super().parsexml(element)
        tag = find(element, "Initiator")
        initiator_id = None if tag is None else findtext(tag, "ID")
        initiator_name = None if tag is None else findtext(tag, "DisplayName")
        tag = find(element, "Owner")
        owner_id = None if tag is None else findtext(tag, "ID")
        owner_name = None if tag is None else findtext(tag, "DisplayName")
        return cls(
            bucket_name=findtext(element, "Bucket"),
            object_name=findtext(element, "Key"),
            initiator_id=initiator_id,
            initiator_name=initiator_name,
            owner_id=owner_id,
            owner_name=owner_name,
            storage_class=findtext(element, "StorageClass"),
            part_number_marker=part_number_marker,
            next_part_number_marker=next_part_number_marker,
            max_parts=max_parts,
            is_truncated=is_truncated,
            parts=parts,
        )


################################################################################
###########                         API responses                    ###########
################################################################################


@dataclass(frozen=True)
class GenericResponse:
    """ Generic response of any APIs."""
    headers: HTTPHeaderDict
    bucket_name: Optional[str] = None
    region: Optional[str] = None
    object_name: Optional[str] = None

    def __init__(
            self,
            *,
            headers: HTTPHeaderDict,
            bucket_name: Optional[str] = None,
            region: Optional[str] = None,
            object_name: Optional[str] = None,
    ):
        object.__setattr__(self, "headers", headers)
        object.__setattr__(self, "bucket_name", bucket_name)
        object.__setattr__(self, "region", region)
        object.__setattr__(self, "object_name", object_name)


@dataclass(frozen=True)
class AbortMultipartUploadResponse(GenericResponse):
    """ Response of AbortMultipartUpload API."""
    upload_id: str = ""

    def __init__(
            self,
            *,
            headers: HTTPHeaderDict,
            bucket_name: str,
            region: str,
            object_name: str,
            upload_id: str,
    ):
        super().__init__(
            headers=headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(self, "upload_id", upload_id)


@dataclass(frozen=True)
class CreateMultipartUploadResponse(GenericResponse):
    """ Response of CreateMultipartUpload API."""
    result: InitiateMultipartUploadResult = InitiateMultipartUploadResult(
        "", "", "",
    )

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
            object_name: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(
            self,
            "result",
            unmarshal(InitiateMultipartUploadResult, response.data.decode()),
        )


@dataclass(frozen=True)
class DeleteObjectsResponse(GenericResponse):
    """ Response of DeleteObjects API."""
    result: DeleteResult = DeleteResult()

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
        )
        object.__setattr__(
            self,
            "result",
            unmarshal(DeleteResult, response.data.decode()),
        )


class EventIterable:
    """Context manager friendly event iterable."""

    def __init__(self, func):
        self._func = func
        self._response = None

    def _close_response(self):
        """Close response."""
        if self._response:
            self._response.close()
            self._response.release_conn()
            self._response = None

    def __iter__(self):
        return self

    def _get_records(self):
        """Get event records from response stream."""
        try:
            line = self._response.readline().strip()
            if not line:
                return None
            if hasattr(line, 'decode'):
                line = line.decode()
            event = json.loads(line)
            if event['Records']:
                return event
        except (StopIteration, JSONDecodeError):
            self._close_response()
        return None

    def __next__(self):
        records = None
        while not records:
            if not self._response or self._response.closed:
                self._response = self._func()
            records = self._get_records()
        return records

    def __enter__(self):
        return self

    def __exit__(self, exc_type, value, traceback):
        self._close_response()


@dataclass(frozen=True)
class GenericUploadResponse(GenericResponse):
    """Common response of any object upload API."""
    etag: str = ""
    last_modified: Optional[datetime] = None
    checksum_crc32: Optional[str] = None
    checksum_crc32c: Optional[str] = None
    checksum_crc64nvme: Optional[str] = None
    checksum_sha1: Optional[str] = None
    checksum_sha256: Optional[str] = None
    checksum_type: Optional[str] = None

    def __init__(  # pylint: disable=too-many-positional-arguments
            self,
            *,
            headers: HTTPHeaderDict,
            bucket_name: str,
            region: str,
            object_name: str,
            etag: Optional[str] = None,
            result: Union[
                CopyObjectResult, CompleteMultipartUploadResult, None] = None,
    ):
        super().__init__(
            headers=headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(
            self,
            "etag",
            etag or headers.get("etag", "").replace('"', ""),
        )
        if isinstance(result, CopyObjectResult):
            object.__setattr__(self, "last_modified", result.last_modified)
        object.__setattr__(
            self,
            "checksum_crc32",
            (
                result.checksum_crc32 if result else
                headers.get("x-amz-checksum-crc32")
            ),
        )
        object.__setattr__(
            self,
            "checksum_crc32c",
            (
                result.checksum_crc32c if result else
                headers.get("x-amz-checksum-crc32c")
            ),
        )
        object.__setattr__(
            self,
            "checksum_crc64nvme",
            (
                result.checksum_crc64nvme if result else
                headers.get("x-amz-checksum-crc64nvme")
            ),
        )
        object.__setattr__(
            self,
            "checksum_sha1",
            (
                result.checksum_sha1 if result else
                headers.get("x-amz-checksum-sha1")
            ),
        )
        object.__setattr__(
            self,
            "checksum_sha256",
            (
                result.checksum_sha256 if result else
                headers.get("x-amz-checksum-sha256")
            ),
        )
        object.__setattr__(
            self,
            "checksum_type",
            (
                result.checksum_type if result else
                headers.get("x-amz-checksum-type")
            ),
        )


@dataclass(frozen=True)
class GetObjectAclResponse(GenericResponse):
    """ Response of GetObjectACL API."""
    policy: AccessControlPolicy = AccessControlPolicy()
    version_id: Optional[str] = None

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
            object_name: str,
            version_id: Optional[str] = None,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(
            self,
            "result",
            unmarshal(AccessControlPolicy, response.data.decode()),
        )
        object.__setattr__(self, "version_id", version_id)


@dataclass(frozen=True)
class GetObjectAttributesResponse(GenericResponse):
    """ Response of GetObjectAttributes API."""
    result: GetObjectAttributesOutput = GetObjectAttributesOutput()
    delete_marker: bool = False
    last_modified: Optional[datetime] = None
    version_id: Optional[str] = None

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
            object_name: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(
            self,
            "result",
            unmarshal(GetObjectAttributesOutput, response.data.decode()),
        )
        object.__setattr__(
            self,
            "delete_marker",
            response.headers.get("x-amz-delete-marker"),
        )
        last_modified = response.headers.get("Last-Modified")
        if last_modified:
            object.__setattr__(
                self,
                "last_modified",
                from_http_header(last_modified),
            )
        object.__setattr__(
            self,
            "version_id",
            response.headers.get("x-amz-version-id"),
        )


@dataclass(frozen=True)
class HeadBucketResponse(GenericResponse):
    """ Response of HeadBucket API."""
    bucket_arn: Optional[str] = None
    location_type: Optional[str] = None
    location_name: Optional[str] = None
    access_point_alias: Optional[str] = None

    def __init__(
            self,
            *,
            headers: HTTPHeaderDict,
            bucket_name: str,
            region: str,
    ):
        super().__init__(
            headers=headers,
            bucket_name=bucket_name,
            region=region,
        )
        object.__setattr__(
            self,
            "bucket_arn",
            headers.get("x-amz-bucket-arn"),
        )
        object.__setattr__(
            self,
            "location_type",
            headers.get("x-amz-bucket-location-type"),
        )
        object.__setattr__(
            self,
            "location_name",
            headers.get("x-amz-bucket-location-name"),
        )
        object.__setattr__(
            self,
            "access_point_alias",
            headers.get("x-amz-access-point-alias"),
        )


@dataclass(frozen=True)
class HeadObjectResponse(GenericResponse):
    """ Response of HeadObject API."""
    etag: str = ""
    size: int = 0
    delete_marker: bool = False
    last_modified: Optional[datetime] = None
    lock_mode: Optional[str] = None
    lock_retain_until_date: Optional[datetime] = None
    lock_legal_hold: bool = False
    checksums: Optional[dict[Algorithm, str]] = None
    checksum_type: Optional[ChecksumType] = None
    user_metadata: Optional[HTTPHeaderDict] = None

    def __init__(
            self,
            *,
            headers: HTTPHeaderDict,
            bucket_name: str,
            region: str,
            object_name: str,
    ):
        super().__init__(
            headers=headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(
            self,
            "etag",
            headers.get("etag", "").replace('"', ""),
        )
        object.__setattr__(
            self,
            "size",
            int(headers.get("content-length", "0")),
        )
        object.__setattr__(
            self,
            "delete_marker",
            headers.get("x-amz-delete-marker", "").lower() == "true",
        )
        value = headers.get("last-modified")
        object.__setattr__(
            self,
            "last_modified",
            from_http_header(value) if value is not None else None,
        )
        object.__setattr__(
            self,
            "lock_mode",
            headers.get("x-amz-object-lock-mode", None),
        )
        value = headers.get("x-amz-object-lock-retain-until-date")
        object.__setattr__(
            self,
            "lock_retain_until_date",
            from_iso8601utc(value) if value is not None else None,
        )
        object.__setattr__(
            self,
            "lock_legal_hold",
            headers.get("x-amz-object-lock-legal-hold", "") == "ON",
        )
        mapping = {
            "x-amz-checksum-crc32": Algorithm.CRC32,
            "x-amz-checksum-crc32c": Algorithm.CRC32C,
            "x-amz-checksum-crc64nvme": Algorithm.CRC64NVME,
            "x-amz-checksum-sha1": Algorithm.SHA1,
            "x-amz-checksum-sha256": Algorithm.SHA256,
        }
        checksums = {}
        for name, algo in mapping.items():
            checksum = self.headers.get(name)
            if checksum:
                checksums[algo] = checksum
        object.__setattr__(self, "checksums", checksums)
        value = headers.get("x-amz-checksum-type")
        if value:
            object.__setattr__(self, "checksum_type", ChecksumType(value))
        user_metadata = HTTPHeaderDict()
        for name, value in headers.items():
            lower_name = name.lower()
            if lower_name.startswith("x-amz-meta-"):
                key = lower_name[len("x-amz-meta-"):]
                user_metadata[key] = value
        object.__setattr__(self, "user_metadata", user_metadata)

    @property
    def version_id(self) -> Optional[str]:
        """Get version ID."""
        return self.headers.get("x-amz-version-id")

    @property
    def content_type(self) -> Optional[str]:
        """Get content-type."""
        return self.headers.get("content-type")


@dataclass(frozen=True)
class ListBucketsResponse(GenericResponse):
    """ Response of ListBuckets API."""
    result: ListAllMyBucketsResult = ListAllMyBucketsResult()

    def __init__(self, *, response: HTTPResponse, region: Optional[str]):
        super().__init__(headers=response.headers, region=region)
        object.__setattr__(
            self,
            "result",
            unmarshal(ListAllMyBucketsResult, response.data.decode()),
        )


@dataclass(frozen=True)
class ListMultipartUploadsResponse(GenericResponse):
    """ Response of ListMultipartUploads API."""
    result: ListMultipartUploadsResult = ListMultipartUploadsResult()

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
        )
        object.__setattr__(
            self,
            "result",
            unmarshal(ListMultipartUploadsResult, response.data.decode()),
        )


@dataclass(frozen=True)
class ListPartsResponse(GenericResponse):
    """ Response of ListParts API."""
    result: ListPartsResult = ListPartsResult()

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
            object_name: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(
            self,
            "result",
            unmarshal(ListPartsResult, response.data.decode()),
        )


@dataclass(frozen=True)
class ObjectWriteResponse(GenericUploadResponse):
    """Response of any APIs doing object creation."""
    version_id: Optional[str] = None

    def __init__(  # pylint: disable=too-many-positional-arguments
            self,
            *,
            headers: HTTPHeaderDict,
            bucket_name: str,
            region: str,
            object_name: str,
            etag: Optional[str] = None,
            version_id: Optional[str] = None,
            result: Union[
                CopyObjectResult, CompleteMultipartUploadResult, None] = None,
    ):
        super().__init__(
            headers=headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
            etag=etag,
            result=result,
        )
        object.__setattr__(
            self,
            "version_id",
            version_id or headers.get("x-amz-version-id"),
        )


@dataclass(frozen=True)
class PutObjectFanOutResponse(GenericResponse):
    """ Response of PutObjectFanOut API."""
    results: List[Result] = field(default_factory=list)

    def __init__(
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
        )

        def to_result(result):
            """Create new result."""
            return PutObjectFanOutResponse.Result(
                key=result["key"],
                etag=result["etag"],
                version_id=result.get("versionId"),
                last_modified=(
                    to_iso8601utc(result.get("lastModified"))
                    if result.get("lastModified") else None
                ),
                error=result.get("error"),
            )
        object.__setattr__(
            self,
            "results",
            [
                to_result(HTTPHeaderDict(json.loads(line)))
                for line in response if line
            ],
        )

    @dataclass(frozen=True)
    class Result:
        """PutObjectFanOut result."""
        key: str
        etag: str
        version_id: Optional[str] = None
        last_modified: Optional[datetime] = None
        error: Optional[str] = None


class GetObjectResponse(GenericResponse, BufferedIOBase):
    """GetObject response, file-like and BufferedIOBase-compatible."""
    version_id: Optional[str] = None

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        *,
        response: HTTPResponse,
        bucket_name: str,
        region: str,
        object_name: str,
        version_id: Optional[str] = None,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        self._response = response
        object.__setattr__(self, "version_id", version_id)

    def __enter__(self) -> GetObjectResponse:
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.close()

    def readable(self) -> bool:  # type: ignore[override]
        """Return True: this stream is readable."""
        return True

    def writable(self) -> bool:  # type: ignore[override]
        """Return False: this stream is not writable."""
        return False

    def seekable(self) -> bool:  # type: ignore[override]
        """S3 object stream is not seekable by default."""
        return False

    def close(self) -> None:  # type: ignore[override]
        """Close response and release network resources."""
        try:
            # Close the underlying response
            self._response.close()
            self._response.release_conn()
        finally:
            # Mark this BufferedIOBase as closed
            super().close()

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        """
        Read up to `size` bytes from the stream.

        If size is -1 (default), read until EOF.
        """
        return self._response.read(size)

    def readinto(self, b) -> int:  # type: ignore[override]
        """
        Read bytes into a pre-allocated, writable bytes-like object `b`.

        Returns the number of bytes read (0 on EOF).
        """
        # Determine how many bytes to request
        length = len(b)
        data = self._response.read(length)
        n = len(data)
        b[:n] = data
        return n

    def stream(self, num_bytes: int = 32 * 1024):
        """
        Stream data in chunks of `num_bytes`.

        This is a convenience wrapper over the underlying HTTPResponse.stream().
        """
        yield from self._response.stream(num_bytes)


class PromptObjectResponse(GenericResponse, BufferedIOBase):
    """PromptObject response, file-like and BufferedIOBase-compatible."""

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        *,
        response: HTTPResponse,
        bucket_name: str,
        region: str,
        object_name: str,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        self._response = response

    def __enter__(self) -> PromptObjectResponse:
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.close()

    def readable(self) -> bool:  # type: ignore[override]
        """Return True: this stream is readable."""
        return True

    def writable(self) -> bool:  # type: ignore[override]
        """Return False: this stream is not writable."""
        return False

    def seekable(self) -> bool:  # type: ignore[override]
        """S3 object stream is not seekable by default."""
        return False

    def close(self) -> None:  # type: ignore[override]
        """Close response and release network resources."""
        try:
            # Close the underlying response
            self._response.close()
            self._response.release_conn()
        finally:
            # Mark this BufferedIOBase as closed
            super().close()

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        """
        Read up to `size` bytes from the stream.

        If size is -1 (default), read until EOF.
        """
        return self._response.read(size)

    def readinto(self, b) -> int:  # type: ignore[override]
        """
        Read bytes into a pre-allocated, writable bytes-like object `b`.

        Returns the number of bytes read (0 on EOF).
        """
        # Determine how many bytes to request
        length = len(b)
        data = self._response.read(length)
        n = len(data)
        b[:n] = data
        return n

    def stream(self, num_bytes: int = 32 * 1024):
        """
        Stream data in chunks of `num_bytes`.

        This is a convenience wrapper over the underlying HTTPResponse.stream().
        """
        yield from self._response.stream(num_bytes)


class SelectObjectResponse(GenericResponse):
    """
    BufferedIOBase compatible reader represents response data of
    Minio.select_object_content() API.
    """

    def __init__(  # pylint: disable=too-many-positional-arguments
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
            object_name: str):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        self._response = response
        self._stats = None
        self._payload = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        return self.close()

    def readable(self):  # pylint: disable=no-self-use
        """Return this is readable."""
        return True

    def writeable(self):  # pylint: disable=no-self-use
        """Return this is not writeable."""
        return False

    def close(self):
        """Close response and release network resources."""
        self._response.close()
        self._response.release_conn()

    def stats(self):
        """Get stats information."""
        return self._stats

    def _read(self):
        """Read and decode response."""
        if self._response.isclosed():
            return 0

        prelude = self._read_fully(self._response, 8)
        prelude_crc = self._read_fully(self._response, 4)
        if self._crc32(prelude) != self._int(prelude_crc):
            raise IOError(
                f"prelude CRC mismatch; expected: {self._crc32(prelude)}, "
                f"got: {self._int(prelude_crc)}"
            )

        total_length = self._int(prelude[:4])
        data = self._read_fully(self._response, total_length - 8 - 4 - 4)
        message_crc = self._int(self._read_fully(self._response, 4))
        if self._crc32(prelude + prelude_crc + data) != message_crc:
            raise IOError(
                f"message CRC mismatch; "
                f"expected: {self._crc32(prelude + prelude_crc + data)}, "
                f"got: {message_crc}"
            )

        header_length = SelectObjectResponse._int(prelude[4:])
        headers = SelectObjectResponse._decode_header(data[:header_length])

        if headers.get(":message-type") == "error":
            raise MinioException(
                f"{headers.get(':error-code')}: "
                f"{headers.get(':error-message')}"
            )

        if headers.get(":event-type") == "End":
            return 0

        payload_length = total_length - header_length - 16
        if headers.get(":event-type") == "Cont" or payload_length < 1:
            return self._read()

        payload = data[header_length:header_length+payload_length]

        if headers.get(":event-type") in ["Progress", "Stats"]:
            self._stats = SelectObjectResponse.Stats(payload)
            return self._read()

        if headers.get(":event-type") == "Records":
            self._payload = payload
            return len(payload)

        raise MinioException(
            f"unknown event-type {headers.get(':event-type')}",
        )

    def stream(self, num_bytes=32*1024):
        """
        Stream extracted payload from response data. Upon completion, caller
        should call self.close() to release network resources.
        """
        while self._read() > 0:
            while self._payload:
                result = self._payload
                if num_bytes < len(self._payload):
                    result = self._payload[:num_bytes]
                self._payload = self._payload[len(result):]
                yield result

    @staticmethod
    def _read_fully(reader, size):
        """Wrapper to RawIOBase.read() to error out on short reads."""
        data = reader.read(size)
        if len(data) != size:
            raise IOError("insufficient data")
        return data

    @staticmethod
    def _int(data):
        """Convert byte data to big-endian int."""
        return int.from_bytes(data, byteorder="big")

    @staticmethod
    def _crc32(data):
        """Wrapper to binascii.crc32()."""
        return crc32(data) & 0xffffffff

    @staticmethod
    def _decode_header(data):
        """Decode header data."""
        reader = BytesIO(data)
        headers = {}
        while True:
            length = reader.read(1)
            if not length:
                break
            name = SelectObjectResponse._read_fully(
                reader,
                SelectObjectResponse._int(length),
            )
            if SelectObjectResponse._int(
                    SelectObjectResponse._read_fully(reader, 1),
            ) != 7:
                raise IOError("header value type is not 7")
            value = SelectObjectResponse._read_fully(
                reader,
                SelectObjectResponse._int(
                    SelectObjectResponse._read_fully(reader, 2),
                ),
            )
            headers[name.decode()] = value.decode()
        return headers

    @dataclass(frozen=True)
    class Stats:
        """Progress/Stats information."""
        bytes_scanned: Optional[str] = None
        bytes_processed: Optional[str] = None
        bytes_returned: Optional[str] = None

        def __init__(self, data):
            element = ET.fromstring(data.decode())
            object.__setattr__(
                self,
                "bytes_scanned",
                findtext(element, "BytesScanned"),
            )
            object.__setattr__(
                self,
                "bytes_processed",
                findtext(element, "BytesProcessed"),
            )
            object.__setattr__(
                self,
                "bytes_returned",
                findtext(element, "BytesReturned"),
            )


StatObjectResponse = HeadObjectResponse


@dataclass(frozen=True)
class UploadPartCopyResponse(GenericResponse):
    """ Response of UploadPartCopy API."""
    upload_id: str = ""
    part_number: int = 0
    result: CopyPartResult = CopyPartResult()

    def __init__(  # pylint: disable=too-many-positional-arguments
            self,
            *,
            response: HTTPResponse,
            bucket_name: str,
            region: str,
            object_name: str,
            upload_id: str,
            part_number: int,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=bucket_name,
            region=region,
            object_name=object_name,
        )
        object.__setattr__(self, "upload_id", upload_id)
        object.__setattr__(self, "part_number", part_number)
        object.__setattr__(
            self,
            "result",
            unmarshal(CopyPartResult, response.data.decode()),
        )

    @property
    def part(self) -> Part:
        """Get part information."""
        return Part.new(self.result, self.part_number)


@dataclass(frozen=True)
class UploadPartResponse(GenericResponse):
    """ Response of UploadPart API."""
    upload_id: str = ""
    part: Part = Part()

    def __init__(  # pylint: disable=too-many-positional-arguments
            self,
            *,
            response: ObjectWriteResponse,
            upload_id: str,
            part_number: int,
    ):
        super().__init__(
            headers=response.headers,
            bucket_name=response.bucket_name,
            region=response.region,
            object_name=response.object_name,
        )
        part = Part(
            part_number=part_number,
            etag=response.etag,
            checksum_crc32=response.checksum_crc32,
            checksum_crc32c=response.checksum_crc32c,
            checksum_crc64nvme=response.checksum_crc64nvme,
            checksum_sha1=response.checksum_sha1,
            checksum_sha256=response.checksum_sha256,
        )
        object.__setattr__(self, "upload_id", upload_id)
        object.__setattr__(self, "part", part)
