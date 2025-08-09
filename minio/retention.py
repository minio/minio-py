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

"""Request/response of PutObjectRetention and GetObjectRetention APIs."""

from __future__ import absolute_import, annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .commonconfig import COMPLIANCE, GOVERNANCE
from .time import from_iso8601utc, to_iso8601utc
from .xml import Element, SubElement, findtext

A = TypeVar("A", bound="Retention")


@dataclass(frozen=True)
class Retention:
    """Retention configuration."""

    mode: str
    retain_until_date: datetime

    def __post_init__(self):
        if self.mode not in [GOVERNANCE, COMPLIANCE]:
            raise ValueError(f"mode must be {GOVERNANCE} or {COMPLIANCE}")
        if not isinstance(self.retain_until_date, datetime):
            raise ValueError(
                "retain until date must be datetime type",
            )

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
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
