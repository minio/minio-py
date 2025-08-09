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

"""Request/response of PutBucketEncryption and GetBucketEncryption APIs."""

from __future__ import absolute_import, annotations

from abc import ABC
from dataclasses import dataclass
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .xml import Element, SubElement, find, findtext

AES256 = "AES256"
AWS_KMS = "aws:kms"

A = TypeVar("A", bound="Rule")


@dataclass(frozen=True)
class Rule(ABC):
    """Server-side encryption rule. """

    sse_algorithm: str
    kms_master_key_id: Optional[str] = None

    @classmethod
    def new_sse_s3_rule(cls: Type[A]) -> A:
        """Create SSE-S3 rule."""
        return cls(sse_algorithm=AES256)

    @classmethod
    def new_sse_kms_rule(
            cls: Type[A],
            kms_master_key_id: Optional[str] = None,
    ) -> A:
        """Create new SSE-KMS rule."""
        return cls(sse_algorithm=AWS_KMS, kms_master_key_id=kms_master_key_id)

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        element = cast(
            ET.Element,
            find(element, "ApplyServerSideEncryptionByDefault", True),
        )
        return cls(
            sse_algorithm=cast(str, findtext(element, "SSEAlgorithm", True)),
            kms_master_key_id=findtext(element, "KMSMasterKeyID"),
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "Rule")
        tag = SubElement(element, "ApplyServerSideEncryptionByDefault")
        SubElement(tag, "SSEAlgorithm", self.sse_algorithm)
        if self.kms_master_key_id is not None:
            SubElement(tag, "KMSMasterKeyID", self.kms_master_key_id)
        return element


B = TypeVar("B", bound="SSEConfig")


@dataclass(frozen=True)
class SSEConfig:
    """server-side encryption configuration."""

    rule: Rule

    def __post_init__(self):
        if not self.rule:
            raise ValueError("rule must be provided")

    @classmethod
    def fromxml(cls: Type[B], element: ET.Element) -> B:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Rule", True))
        return cls(Rule.fromxml(element))

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("ServerSideEncryptionConfiguration")
        self.rule.toxml(element)
        return element
