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

"""Tagging for bucket and object."""

from __future__ import absolute_import, annotations

from dataclasses import dataclass
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .commonconfig import Tags
from .xml import Element, SubElement, find

A = TypeVar("A", bound="Tagging")


@dataclass(frozen=True)
class Tagging:
    """Tagging for buckets and objects."""

    tags: Optional[Tags]

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "TagSet", True))
        tags = (
            None if find(element, "Tag") is None
            else Tags.fromxml(element)
        )
        return cls(tags=tags)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("Tagging")
        if self.tags:
            self.tags.toxml(SubElement(element, "TagSet"))
        return element
