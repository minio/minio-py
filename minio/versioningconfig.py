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

"""Request/response of PutBucketVersioning and GetBucketVersioning APIs."""

from __future__ import absolute_import, annotations

from typing import Type, TypeVar
from xml.etree import ElementTree as ET

from .commonconfig import DISABLED, ENABLED
from .xml import Element, SubElement, findtext

OFF = "Off"
SUSPENDED = "Suspended"

A = TypeVar("A", bound="VersioningConfig")


class VersioningConfig:
    """Versioning configuration."""

    def __init__(
        self,
        status: str | None = None,
        mfa_delete: str | None = None,
        excluded_prefixes: list[str] | None = None,
    ):
        if status is not None and status not in [ENABLED, SUSPENDED]:
            raise ValueError(f"status must be {ENABLED} or {SUSPENDED}")
        if mfa_delete is not None and mfa_delete not in [ENABLED, DISABLED]:
            raise ValueError(f"MFA delete must be {ENABLED} or {DISABLED}")
        if excluded_prefixes is not None and not isinstance(excluded_prefixes, list):
            raise ValueError("Excluded prefixes must be a list")
        self._status = status
        self._mfa_delete = mfa_delete
        self._excluded_prefixes = excluded_prefixes

    @property
    def status(self) -> str:
        """Get status."""
        return self._status or OFF

    @property
    def mfa_delete(self) -> str | None:
        """Get MFA delete."""
        return self._mfa_delete

    @property
    def excluded_prefixes(self) -> str | None:
        """Get MFA delete."""
        return self._excluded_prefixes

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        status = findtext(element, "Status")
        mfa_delete = findtext(element, "MFADelete")

        excluded_prefixes_tag = element.find("ExcludedPrefixes")
        excluded_prefixes = None
        if excluded_prefixes_tag:
            excluded_prefixes = [
                tag.text for tag in excluded_prefixes_tag.findall("ExcludedPrefix")
            ]

        return cls(status, mfa_delete, excluded_prefixes)

    def toxml(self, element: ET.Element | None) -> ET.Element:
        """Convert to XML."""
        element = Element("VersioningConfiguration")
        if self._status:
            SubElement(element, "Status", self._status)
        if self._mfa_delete:
            SubElement(element, "MFADelete", self._mfa_delete)
        if self._excluded_prefixes:
            SubElement(element, "ExcludedPrefixes")
            for prefix in self._excluded_prefixes:
                SubElement(element, "ExcludedPrefix", prefix)
        return element
