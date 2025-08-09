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

"""Request/response of DeleteObjects API."""

from __future__ import absolute_import, annotations

from dataclasses import dataclass
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .xml import Element, SubElement, findall, findtext


@dataclass(frozen=True)
class DeleteObject:
    """Delete object request information."""

    name: str
    version_id: Optional[str] = None

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Object")
        SubElement(element, "Key", self.name)
        if self.version_id is not None:
            SubElement(element, "VersionId", self.version_id)
        return element


@dataclass(frozen=True)
class DeleteRequest:
    """Delete object request."""

    object_list: list[DeleteObject]
    quiet: bool = False

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("Delete")
        if self.quiet:
            SubElement(element, "Quiet", "true")
        for obj in self.object_list:
            obj.toxml(element)
        return element


A = TypeVar("A", bound="DeletedObject")


@dataclass(frozen=True)
class DeletedObject:
    """Deleted object information."""

    name: str
    version_id: Optional[str]
    delete_marker: bool
    delete_marker_version_id: Optional[str]

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        name = cast(str, findtext(element, "Key", True))
        version_id = findtext(element, "VersionId")
        delete_marker = findtext(element, "DeleteMarker")
        delete_marker_version_id = findtext(element, "DeleteMarkerVersionId")
        return cls(
            name=name,
            version_id=version_id,
            delete_marker=(
                delete_marker is not None and delete_marker.title() == "True"
            ),
            delete_marker_version_id=delete_marker_version_id,
        )


B = TypeVar("B", bound="DeleteError")


@dataclass(frozen=True)
class DeleteError:
    """Delete error information."""

    code: str
    message: Optional[str]
    name: Optional[str]
    version_id: Optional[str]

    @classmethod
    def fromxml(cls: Type[B], element: ET.Element) -> B:
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


C = TypeVar("C", bound="DeleteResult")


@dataclass(frozen=True)
class DeleteResult:
    """Delete object result."""

    object_list: list[DeletedObject]
    error_list: list[DeleteError]

    @classmethod
    def fromxml(cls: Type[C], element: ET.Element) -> C:
        """Create new object with values from XML element."""
        elements = findall(element, "Deleted")
        object_list = []
        for tag in elements:
            object_list.append(DeletedObject.fromxml(tag))
        elements = findall(element, "Error")
        error_list = []
        for tag in elements:
            error_list.append(DeleteError.fromxml(tag))
        return cls(object_list=object_list, error_list=error_list)
