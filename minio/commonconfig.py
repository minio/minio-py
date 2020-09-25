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

"""Common request/response configuration of S3 APIs."""
# pylint: disable=invalid-name

from __future__ import absolute_import

from abc import ABCMeta

from .xml import SubElement, find, findall, findtext

DISABLED = "Disabled"
ENABLED = "Enabled"
_MAX_KEY_LENGTH = 128
_MAX_VALUE_LENGTH = 256
_MAX_OBJECT_TAG_COUNT = 10
_MAX_TAG_COUNT = 50


class Tags(dict):
    """dict extended to bucket/object tags."""

    def __init__(self, for_object=False):
        self._for_object = for_object
        super().__init__()

    def __setitem__(self, key, value):
        limit = _MAX_OBJECT_TAG_COUNT if self._for_object else _MAX_TAG_COUNT
        if len(self) == limit:
            raise ValueError(
                "only {0} {1} tags are allowed".format(
                    limit, "object" if self._for_object else "bucket",
                ),
            )
        if not key or len(key) > _MAX_KEY_LENGTH or "&" in key:
            raise ValueError("invalid tag key '{0}'".format(key))
        if value is None or len(value) > _MAX_VALUE_LENGTH or "&" in value:
            raise ValueError("invalid tag value '{0}'".format(value))
        super().__setitem__(key, value)

    @classmethod
    def fromxml(cls, element):
        """Create new object with values from XML element."""
        elements = findall(element, "Tag")
        obj = cls()
        for tag in elements:
            key = findtext(tag, "Key", True)
            value = findtext(tag, "Value", True)
            obj[key] = value
        return obj

    def toxml(self, element):
        """Convert to XML."""
        for key, value in self.items():
            tag = SubElement(element, "Tag")
            SubElement(tag, "Key", key)
            SubElement(tag, "Value", value)
        return element


class Tag:
    """Tag."""

    def __init__(self, key, value):
        if not key:
            raise ValueError("key must be provided")
        if value is None:
            raise ValueError("value must be provided")
        self._key = key
        self._value = value

    @property
    def key(self):
        """Get key."""
        return self._key

    @property
    def value(self):
        """Get value."""
        return self._value

    @classmethod
    def fromxml(cls, element):
        """Create new object with values from XML element."""
        element = find(element, "Tag")
        key = findtext(element, "Key", True)
        value = findtext(element, "Value", True)
        return cls(key, value)

    def toxml(self, element):
        """Convert to XML."""
        element = SubElement(element, "Tag")
        SubElement(element, "Key", self._key)
        SubElement(element, "Value", self._value)
        return element


class AndOperator:
    """AND operator."""

    def __init__(self, prefix=None, tags=None):
        if prefix is None and not tags:
            raise ValueError("at least prefix or tags must be provided")
        self._prefix = prefix
        self._tags = tags

    @property
    def prefix(self):
        """Get prefix."""
        return self._prefix

    @property
    def tags(self):
        """Get tags."""
        return self._tags

    @classmethod
    def fromxml(cls, element):
        """Create new object with values from XML element."""
        element = find(element, "And")
        prefix = findtext(element, "Prefix")
        tags = (
            None if find(element, "Tag") is None
            else Tags.fromxml(element)
        )
        return cls(prefix, tags)

    def toxml(self, element):
        """Convert to XML."""
        element = SubElement(element, "And")
        if self._prefix is not None:
            SubElement(element, "Prefix", self._prefix)
        if self._tags is not None:
            self._tags.toxml(element)
        return element


class Filter:
    """Lifecycle rule filter."""

    def __init__(self, and_operator=None, prefix=None, tag=None):
        valid = (
            (and_operator is not None) ^
            (prefix is not None) ^
            (tag is not None)
        )
        if not valid:
            raise ValueError("only one of and, prefix or tag must be provided")
        if prefix is not None and not prefix:
            raise ValueError("prefix must not be empty")
        self._and_operator = and_operator
        self._prefix = prefix
        self._tag = tag

    @property
    def and_operator(self):
        """Get AND operator."""
        return self._and_operator

    @property
    def prefix(self):
        """Get prefix."""
        return self._prefix

    @property
    def tag(self):
        """Get tag."""
        return self._tag

    @classmethod
    def fromxml(cls, element):
        """Create new object with values from XML element."""
        element = find(element, "Filter")
        and_operator = (
            None if find(element, "And") is None
            else AndOperator.fromxml(element)
        )
        prefix = findtext(element, "Prefix")
        tag = None if find(element, "Tag") is None else Tag.fromxml(element)
        return cls(and_operator, prefix, tag)

    def toxml(self, element):
        """Convert to XML."""
        element = SubElement(element, "Filter")
        if self._and_operator:
            self._and_operator.toxml(element)
        if self._prefix is not None:
            SubElement(element, "Prefix", self._prefix)
        if self._tag is not None:
            self._tag.toxml(element)
        return element


class BaseRule:
    """Base rule class for Replication and Lifecycle."""
    __metaclass__ = ABCMeta

    def __init__(self, rule_filter=None, rule_id=None):
        if rule_id is not None:
            rule_id = rule_id.strip()
            if not rule_id:
                raise ValueError("rule ID must be non-empty string")
            if len(rule_id) > 255:
                raise ValueError("rule ID must not exceed 255 characters")
        self._rule_filter = rule_filter
        self._rule_id = rule_id

    @property
    def rule_filter(self):
        """Get replication rule filter."""
        return self._rule_filter

    @property
    def rule_id(self):
        """Get rule ID."""
        return self._rule_id

    @staticmethod
    def parsexml(element):
        """Parse XML and return filter and ID."""
        return (
            None if find(element, "Filter") is None
            else Filter.fromxml(element)
        ), findtext(element, "ID")

    def toxml(self, element):
        """Convert to XML."""
        if self._rule_filter:
            self._rule_filter.toxml(element)
        if self._rule_id is not None:
            SubElement(element, "ID", self._rule_id)
        return element


def check_status(status):
    """Validate status."""
    if status not in [ENABLED, DISABLED]:
        raise ValueError("status must be 'Enabled' or 'Disabled'")
