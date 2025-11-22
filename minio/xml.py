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

"""XML encoding and decoding functions."""

from __future__ import annotations

import io
from typing import Optional, TypeVar
from xml.etree import ElementTree as ET

from typing_extensions import Protocol

_S3_NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"


def Element(  # pylint: disable=invalid-name
    tag: str,
    namespace: str = _S3_NAMESPACE,
) -> ET.Element:
    """Create ElementTree.Element with tag and namespace."""
    return ET.Element(tag, {"xmlns": namespace} if namespace else {})


def SubElement(  # pylint: disable=invalid-name
    parent: ET.Element, tag: str, text: Optional[str] = None
) -> ET.Element:
    """Create ElementTree.SubElement on parent with tag and text."""
    element = ET.SubElement(parent, tag)
    if text is not None:
        element.text = text
    return element


def _namespaced(element: ET.Element, name: str) -> tuple[str, dict[str, str]]:
    """Namespace arguments for find and findall."""
    def _get_namespace() -> str:
        """Exact namespace if found."""
        start = element.tag.find("{")
        if start < 0:
            return ""
        start += 1
        end = element.tag.find("}")
        if end < 0:
            return ""
        return element.tag[start:end]

    namespace = _get_namespace()
    if namespace:
        name = "/".join(f"ns:{token}" for token in name.split("/"))
        return name, {"ns": namespace}
    return name, {}


def findall(element: ET.Element, name: str) -> list[ET.Element]:
    """Namespace aware ElementTree.Element.findall()."""
    name, namespaces = _namespaced(element, name)
    return element.findall(name, namespaces=namespaces)


def find(
        element: ET.Element,
        name: str,
        strict: bool = False,
) -> Optional[ET.Element]:
    """Namespace aware ElementTree.Element.find()."""
    name, namespaces = _namespaced(element, name)
    elem = element.find(name, namespaces=namespaces)
    if strict and elem is None:
        raise ValueError(f"XML element <{name}> not found")
    return elem


def findtext(
    element: ET.Element,
    name: str,
    strict: bool = False,
    default: Optional[str] = None,
) -> Optional[str]:
    """
    Namespace aware ElementTree.Element.findtext() with strict flag
    raises ValueError if element name not exist.
    """
    elem = find(element, name, strict=strict)
    return default if elem is None else (elem.text or "")


UnmarshalT = TypeVar("UnmarshalT", bound="UnmarshalProtocol")


class UnmarshalProtocol(Protocol):
    """typing stub for class with `fromxml` method"""

    @classmethod
    def fromxml(cls: type[UnmarshalT], element: ET.Element) -> UnmarshalT:
        """
        Create object by values from XML element.
        Code discipline:
        1. Do not use find() to look for its own `Element` if needed.
        """


def unmarshal(cls: type[UnmarshalT], xmlstring: str) -> UnmarshalT:
    """Unmarshal given XML string to an object of passed class."""
    return cls.fromxml(ET.fromstring(xmlstring))


def getbytes(element: ET.Element) -> bytes:
    """Convert ElementTree.Element to bytes."""
    with io.BytesIO() as data:
        ET.ElementTree(element).write(
            data,
            encoding=None,
            xml_declaration=False,
        )
        return data.getvalue()


class MarshalT(Protocol):
    """typing stub for class with `toxml` method"""

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """
        Convert python object to ElementTree.Element.
        Code discipline:
        1. Do not create its own `SubElement` if needed.
        2. Always return passed `Element`.
        3. For root, `element` argument is always `None` hence
           root `Element` must be created.
        """


def marshal(obj: MarshalT) -> bytes:
    """Get XML data as bytes of ElementTree.Element."""
    return getbytes(obj.toxml(None))
