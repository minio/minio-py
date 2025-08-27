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

"""
Request/response of PutObjectLockConfiguration and GetObjectLockConfiguration
APIs.
"""

from __future__ import absolute_import, annotations

from dataclasses import dataclass
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .commonconfig import COMPLIANCE, ENABLED, GOVERNANCE
from .xml import Element, SubElement, find, findtext

DAYS = "Days"
YEARS = "Years"

A = TypeVar("A", bound="ObjectLockConfig")


@dataclass(frozen=True)
class ObjectLockConfig:
    """Object lock configuration."""

    mode: Optional[str]
    duration: Optional[int]
    duration_unit: Optional[str]

    def __post_init__(self):
        if (self.mode is not None) ^ (self.duration is not None):
            if self.mode is None:
                raise ValueError("mode must be provided")
            raise ValueError("duration must be provided")
        if self.mode is not None and self.mode not in [GOVERNANCE, COMPLIANCE]:
            raise ValueError(f"mode must be {GOVERNANCE} or {COMPLIANCE}")
        if (
                self.duration is not None and
                self.duration_unit not in [DAYS, YEARS]
        ):
            raise ValueError(f"duration unit must be {DAYS} or {YEARS}")
        if self.duration_unit:
            object.__setattr__(
                self, "duration_unit", self.duration_unit.title(),
            )

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        elem = find(element, "Rule")
        if elem is None:
            return cls(None, None, None)
        elem = cast(ET.Element, find(elem, "DefaultRetention", True))
        mode = findtext(elem, "Mode")
        duration_unit = DAYS
        duration = findtext(elem, duration_unit)
        if not duration:
            duration_unit = YEARS
            duration = findtext(elem, duration_unit)
        if not duration:
            raise ValueError(f"XML element <{DAYS}> or <{YEARS}> not found")
        return cls(
            mode=mode,
            duration=int(duration),
            duration_unit=duration_unit,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("ObjectLockConfiguration")
        SubElement(element, "ObjectLockEnabled", ENABLED)
        if self.mode:
            rule = SubElement(element, "Rule")
            retention = SubElement(rule, "DefaultRetention")
            SubElement(retention, "Mode", self.mode)
            if not self.duration_unit:
                raise ValueError("duration unit must be provided")
            SubElement(retention, self.duration_unit, str(self.duration))
        return element
