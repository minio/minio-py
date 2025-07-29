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

"""
Request/response of PutBucketLifecycleConfiguration and
GetBucketLifecycleConfiguration APIs.
"""
# pylint: disable=invalid-name

from __future__ import absolute_import, annotations

from abc import ABC
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .commonconfig import BaseRule
from .time import from_iso8601utc, to_iso8601utc
from .xml import Element, SubElement, find, findall, findtext


@dataclass(frozen=True)
class DateDays(ABC):
    """Base class holds date and days of Transition and Expiration."""
    date: Optional[datetime] = None
    days: Optional[int] = None

    @staticmethod
    def parsexml(
            element: ET.Element) -> tuple[Optional[datetime], Optional[int]]:
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


A = TypeVar("A", bound="Transition")


@dataclass(frozen=True)
class Transition(DateDays):
    """Transition."""
    storage_class: Optional[str] = None

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Transition", True))
        date, days = cls.parsexml(element)
        return cls(date, days, findtext(element, "StorageClass"))

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Transition")
        super().toxml(element)
        if self.storage_class:
            SubElement(element, "StorageClass", self.storage_class)
        return element


B = TypeVar("B", bound="NoncurrentVersionTransition")


@dataclass(frozen=True)
class NoncurrentVersionTransition:
    """Noncurrent version transition."""
    noncurrent_days: Optional[int] = None
    storage_class: Optional[str] = None
    newer_noncurrent_versions: Optional[int] = None

    @classmethod
    def fromxml(cls: Type[B], element: ET.Element) -> B:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element,
            find(element, "NoncurrentVersionTransition", True),
        )
        noncurrent_days = findtext(element, "NoncurrentDays")
        versions = findtext(element, "NewerNoncurrentVersions")
        return cls(
            int(noncurrent_days) if noncurrent_days else None,
            findtext(element, "StorageClass"),
            int(versions) if versions else None,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "NoncurrentVersionTransition")
        if self.noncurrent_days:
            SubElement(element, "NoncurrentDays", str(self.noncurrent_days))
        if self.storage_class:
            SubElement(element, "StorageClass", self.storage_class)
        if self.newer_noncurrent_versions:
            SubElement(element, "NewerNoncurrentVersions",
                       str(self.newer_noncurrent_versions))
        return element


C = TypeVar("C", bound="NoncurrentVersionExpiration")


@dataclass(frozen=True)
class NoncurrentVersionExpiration:
    """Noncurrent version expiration."""
    noncurrent_days: Optional[int] = None
    newer_noncurrent_versions: Optional[int] = None

    @classmethod
    def fromxml(cls: Type[C], element: ET.Element) -> C:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element,
            find(element, "NoncurrentVersionExpiration", True),
        )
        noncurrent_days = findtext(element, "NoncurrentDays")
        versions = findtext(element, "NewerNoncurrentVersions")
        return cls(int(noncurrent_days) if noncurrent_days else None,
                   int(versions) if versions else None)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "NoncurrentVersionExpiration")
        if self.noncurrent_days:
            SubElement(element, "NoncurrentDays", str(self.noncurrent_days))
        if self.newer_noncurrent_versions:
            SubElement(element, "NewerNoncurrentVersions",
                       str(self.newer_noncurrent_versions))
        return element


D = TypeVar("D", bound="Expiration")


@dataclass(frozen=True)
class Expiration(DateDays):
    """Expiration."""
    expired_object_delete_marker: Optional[bool] = None

    @classmethod
    def fromxml(cls: Type[D], element: ET.Element) -> D:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Expiration", True))
        date, days = cls.parsexml(element)
        expired_object_delete_marker = findtext(
            element, "ExpiredObjectDeleteMarker",
        )
        if expired_object_delete_marker is None:
            return cls(date, days, None)

        if expired_object_delete_marker.title() not in ["False", "True"]:
            raise ValueError(
                "value of ExpiredObjectDeleteMarker must be "
                "'True' or 'False'",
            )
        return cls(date, days, expired_object_delete_marker.title() == "True")

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Expiration")
        super().toxml(element)
        if self.expired_object_delete_marker is not None:
            SubElement(
                element,
                "ExpiredObjectDeleteMarker",
                str(self.expired_object_delete_marker).lower(),
            )
        return element


E = TypeVar("E", bound="AbortIncompleteMultipartUpload")


@dataclass(frozen=True)
class AbortIncompleteMultipartUpload:
    """Abort incomplete multipart upload."""
    days_after_initiation: Optional[int] = None

    @classmethod
    def fromxml(cls: Type[E], element: ET.Element) -> E:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element,
            find(element, "AbortIncompleteMultipartUpload", True),
        )
        days_after_initiation = findtext(element, "DaysAfterInitiation")
        return cls(
            int(days_after_initiation) if days_after_initiation else None,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "AbortIncompleteMultipartUpload")
        if self.days_after_initiation:
            SubElement(
                element,
                "DaysAfterInitiation",
                str(self.days_after_initiation),
            )
        return element


F = TypeVar("F", bound="Rule")


@dataclass(frozen=True)
class Rule(BaseRule):
    """Lifecycle rule. """
    abort_incomplete_multipart_upload: Optional[
        AbortIncompleteMultipartUpload] = None
    expiration: Optional[Expiration] = None
    noncurrent_version_expiration: Optional[NoncurrentVersionExpiration] = None
    noncurrent_version_transition: Optional[NoncurrentVersionTransition] = None
    transition: Optional[Transition] = None

    def __post_init__(self):
        if (not self.abort_incomplete_multipart_upload and not self.expiration
            and not self.noncurrent_version_expiration
            and not self.noncurrent_version_transition
                and not self.transition):
            raise ValueError(
                "at least one of action (AbortIncompleteMultipartUpload, "
                "Expiration, NoncurrentVersionExpiration, "
                "NoncurrentVersionTransition or Transition) must be specified "
                "in a rule")

    def _require_subclass_implementation(self) -> None:
        """Dummy abstract method to enforce abstract class behavior."""

    @classmethod
    def fromxml(cls: Type[F], element: ET.Element) -> F:
        """Create new object with values from XML element."""
        status, rule_filter, rule_id = cls.parsexml(element)
        abort_incomplete_multipart_upload = (
            None if find(element, "AbortIncompleteMultipartUpload") is None
            else AbortIncompleteMultipartUpload.fromxml(element)
        )
        expiration = (
            None if find(element, "Expiration") is None
            else Expiration.fromxml(element)
        )
        noncurrent_version_expiration = (
            None if find(element, "NoncurrentVersionExpiration") is None
            else NoncurrentVersionExpiration.fromxml(element)
        )
        noncurrent_version_transition = (
            None if find(element, "NoncurrentVersionTransition") is None
            else NoncurrentVersionTransition.fromxml(element)
        )
        transition = (
            None if find(element, "Transition") is None
            else Transition.fromxml(element)
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
        element = SubElement(element, "Rule")
        super().toxml(element)
        if self.abort_incomplete_multipart_upload:
            self.abort_incomplete_multipart_upload.toxml(element)
        if self.expiration:
            self.expiration.toxml(element)
        if self.noncurrent_version_expiration:
            self.noncurrent_version_expiration.toxml(element)
        if self.noncurrent_version_transition:
            self.noncurrent_version_transition.toxml(element)
        if self.transition:
            self.transition.toxml(element)
        return element


G = TypeVar("G", bound="LifecycleConfig")


@dataclass(frozen=True)
class LifecycleConfig:
    """Lifecycle configuration."""
    rules: list[Rule]

    @classmethod
    def fromxml(cls: Type[G], element: ET.Element) -> G:
        """Create new object with values from XML element."""
        elements = findall(element, "Rule")
        rules = []
        for tag in elements:
            rules.append(Rule.fromxml(tag))
        return cls(rules)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("LifecycleConfiguration")
        for rule in self.rules:
            rule.toxml(element)
        return element
