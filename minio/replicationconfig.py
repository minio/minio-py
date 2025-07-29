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

"""Request/response of PutBucketReplication and GetBucketReplication APIs."""

from __future__ import absolute_import, annotations

from abc import ABC
from dataclasses import dataclass
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .commonconfig import DISABLED, BaseRule, Filter, check_status
from .xml import Element, SubElement, find, findall, findtext

A = TypeVar("A", bound="Status")


@dataclass(frozen=True)
class Status(ABC):
    """Status."""

    status: str

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, cls.__name__, True))
        status = cast(str, findtext(element, "Status", True))
        return cls(status)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, self.__class__.__name__)
        SubElement(element, "Status", self.status)
        return element


@dataclass(frozen=True)
class SseKmsEncryptedObjects(Status):
    """SSE KMS encrypted objects."""


B = TypeVar("B", bound="SourceSelectionCriteria")


@dataclass(frozen=True)
class SourceSelectionCriteria:
    """Source selection criteria."""

    sse_kms_encrypted_objects: Optional[SseKmsEncryptedObjects] = None

    @classmethod
    def fromxml(cls: Type[B], element: ET.Element) -> B:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element,
            find(element, "SourceSelectionCriteria", True),
        )
        return cls(
            None if find(element, "SseKmsEncryptedObjects") is None
            else SseKmsEncryptedObjects.fromxml(element)
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "SourceSelectionCriteria")
        if self.sse_kms_encrypted_objects:
            self.sse_kms_encrypted_objects.toxml(element)
        return element


@dataclass(frozen=True)
class ExistingObjectReplication(Status):
    """Existing object replication."""


@dataclass(frozen=True)
class DeleteMarkerReplication(Status):
    """Delete marker replication."""

    def __init__(self, status=DISABLED):
        super().__init__(status)


C = TypeVar("C", bound="ReplicationTimeValue")


@dataclass(frozen=True)
class ReplicationTimeValue(ABC):
    """Replication time value."""

    minutes: Optional[int] = 15

    @classmethod
    def fromxml(cls: Type[C], element: ET.Element) -> C:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, cls.__name__, True))
        minutes = findtext(element, "Minutes")
        return cls(int(minutes) if minutes else None)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, self.__class__.__name__)
        if self.minutes is not None:
            SubElement(element, "Minutes", str(self.minutes))
        return element


@dataclass(frozen=True)
class Time(ReplicationTimeValue):
    """Time."""


D = TypeVar("D", bound="ReplicationTime")


@dataclass(frozen=True)
class ReplicationTime:
    """Replication time."""

    time: Time
    status: str

    def __post_init__(self,):
        if not self.time:
            raise ValueError("time must be provided")
        check_status(self.status)

    @classmethod
    def fromxml(cls: Type[D], element: ET.Element) -> D:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "ReplicationTime", True))
        time = Time.fromxml(element)
        status = cast(str, findtext(element, "Status", True))
        return cls(time, status)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "ReplicationTime")
        self.time.toxml(element)
        SubElement(element, "Status", self.status)
        return element


@dataclass(frozen=True)
class EventThreshold(ReplicationTimeValue):
    """Event threshold."""


E = TypeVar("E", bound="Metrics")


@dataclass(frozen=True)
class Metrics:
    """Metrics."""

    event_threshold: EventThreshold
    status: str

    def __post_init__(self):
        if not self.event_threshold:
            raise ValueError("event threshold must be provided")
        check_status(self.status)

    @classmethod
    def fromxml(cls: Type[E], element: ET.Element) -> E:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Metrics", True))
        event_threshold = EventThreshold.fromxml(element)
        status = cast(str, findtext(element, "Status", True))
        return cls(event_threshold, status)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Metrics")
        self.event_threshold.toxml(element)
        SubElement(element, "Status", self.status)
        return element


F = TypeVar("F", bound="EncryptionConfig")


@dataclass(frozen=True)
class EncryptionConfig:
    """Encryption configuration."""

    replica_kms_key_id: Optional[str] = None

    @classmethod
    def fromxml(cls: Type[F], element: ET.Element) -> F:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element,
            find(element, "EncryptionConfiguration", True),
        )
        return cls(findtext(element, "ReplicaKmsKeyID"))

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "EncryptionConfiguration")
        SubElement(element, "ReplicaKmsKeyID", self.replica_kms_key_id)
        return element


G = TypeVar("G", bound="AccessControlTranslation")


@dataclass(frozen=True)
class AccessControlTranslation:
    """Access control translation."""

    owner: str = "Destination"

    def __post_init__(self):
        if not self.owner:
            raise ValueError("owner must be provided")

    @classmethod
    def fromxml(cls: Type[G], element: ET.Element) -> G:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element, find(element, "AccessControlTranslation", True),
        )
        owner = cast(str, findtext(element, "Owner", True))
        return cls(owner)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "AccessControlTranslation")
        SubElement(element, "Owner", self.owner)
        return element


H = TypeVar("H", bound="Destination")


@dataclass(frozen=True)
class Destination:
    """Replication destination."""

    bucket_arn: str
    access_control_translation: Optional[AccessControlTranslation] = None
    account: Optional[str] = None
    encryption_config: Optional[EncryptionConfig] = None
    metrics: Optional[Metrics] = None
    replication_time: Optional[ReplicationTime] = None
    storage_class: Optional[str] = None

    def __post_init__(self):
        if not self.bucket_arn:
            raise ValueError("bucket ARN must be provided")

    @classmethod
    def fromxml(cls: Type[H], element: ET.Element) -> H:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Destination", True))
        access_control_translation = (
            None if find(element, "AccessControlTranslation") is None
            else AccessControlTranslation.fromxml(element)
        )
        account = findtext(element, "Account")
        bucket_arn = cast(str, findtext(element, "Bucket", True))
        encryption_config = (
            None if find(element, "EncryptionConfiguration") is None
            else EncryptionConfig.fromxml(element)
        )
        metrics = (
            None if find(element, "Metrics") is None
            else Metrics.fromxml(element)
        )
        replication_time = (
            None if find(element, "ReplicationTime") is None
            else ReplicationTime.fromxml(element)
        )
        storage_class = findtext(element, "StorageClass")
        return cls(bucket_arn, access_control_translation, account,
                   encryption_config, metrics, replication_time, storage_class)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Destination")
        if self.access_control_translation:
            self.access_control_translation.toxml(element)
        if self.account is not None:
            SubElement(element, "Account", self.account)
        SubElement(element, "Bucket", self.bucket_arn)
        if self.encryption_config:
            self.encryption_config.toxml(element)
        if self.metrics:
            self.metrics.toxml(element)
        if self.replication_time:
            self.replication_time.toxml(element)
        if self.storage_class:
            SubElement(element, "StorageClass", self.storage_class)
        return element


I = TypeVar("I", bound="Rule")


@dataclass(frozen=True)
class Rule(BaseRule):
    """Replication rule. """

    destination: Optional[Destination] = None
    delete_marker_replication: Optional[DeleteMarkerReplication] = None
    existing_object_replication: Optional[ExistingObjectReplication] = None
    rule_filter: Optional[Filter] = None
    rule_id: Optional[str] = None
    prefix: Optional[str] = None
    priority: Optional[int] = None
    source_selection_criteria: Optional[SourceSelectionCriteria] = None

    def __post_init__(self):
        if not self.destination:
            raise ValueError("destination must be provided")

    def _require_subclass_implementation(self) -> None:
        """Dummy abstract method to enforce abstract class behavior."""

    @classmethod
    def fromxml(cls: Type[I], element: ET.Element) -> I:
        """Create new object with values from XML element."""
        status, rule_filter, rule_id = cls.parsexml(element)
        delete_marker_replication = (
            None if find(element, "DeleteMarkerReplication") is None
            else DeleteMarkerReplication.fromxml(element)
        )
        destination = Destination.fromxml(element)
        existing_object_replication = (
            None if find(element, "ExistingObjectReplication") is None
            else ExistingObjectReplication.fromxml(element)
        )
        prefix = findtext(element, "Prefix")
        priority = findtext(element, "Priority")
        source_selection_criteria = (
            None if find(element, "SourceSelectionCriteria") is None
            else SourceSelectionCriteria.fromxml(element)
        )

        return cls(
            status=status,
            rule_filter=rule_filter,
            rule_id=rule_id,
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
        element = SubElement(element, "Rule")
        super().toxml(element)
        if self.delete_marker_replication:
            self.delete_marker_replication.toxml(element)
        if self.destination:
            self.destination.toxml(element)
        if self.existing_object_replication:
            self.existing_object_replication.toxml(element)
        if self.prefix is not None:
            SubElement(element, "Prefix", self.prefix)
        if self.priority is not None:
            SubElement(element, "Priority", str(self.priority))
        if self.source_selection_criteria:
            self.source_selection_criteria.toxml(element)
        return element


J = TypeVar("J", bound="ReplicationConfig")


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
    def fromxml(cls: Type[J], element: ET.Element) -> J:
        """Create new object with values from XML element."""
        role = cast(str, findtext(element, "Role", True))
        elements = findall(element, "Rule")
        rules = []
        for tag in elements:
            rules.append(Rule.fromxml(tag))
        return cls(role, rules)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("ReplicationConfiguration")
        SubElement(element, "Role", self.role)
        for rule in self.rules:
            rule.toxml(element)
        return element
