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

from dataclasses import dataclass
from typing import List, Optional, Type, TypeVar, Union, cast
from xml.etree import ElementTree as ET

from .commonconfig import DISABLED, ENABLED
from .xml import Element, SubElement, findall, findtext

OFF = "Off"
SUSPENDED = "Suspended"

A = TypeVar("A", bound="VersioningConfig")


@dataclass(frozen=True)
class VersioningConfig:
    """Versioning configuration."""

    status: Optional[str] = None
    mfa_delete: Optional[str] = None
    excluded_prefixes: Optional[list[str]] = None
    exclude_folders: bool = False

    def __post_init__(self):
        if self.status is not None and self.status not in [ENABLED, SUSPENDED]:
            raise ValueError(f"status must be {ENABLED} or {SUSPENDED}")
        if (
                self.mfa_delete is not None and
                self.mfa_delete not in [ENABLED, DISABLED]
        ):
            raise ValueError(f"MFA delete must be {ENABLED} or {DISABLED}")

    @property
    def status_string(self) -> str:
        """Convert status to status string. """
        return OFF if self.status is None else self.status

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
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
        exclude_folders = findtext(element, "ExcludeFolders") == "true"
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
