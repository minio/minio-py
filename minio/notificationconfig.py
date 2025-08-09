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
Request/response of PutBucketNotificationConfiguration and
GetBucketNotiicationConfiguration APIs.
"""

from __future__ import absolute_import, annotations

from abc import ABC
from dataclasses import dataclass, field
from typing import Optional, Type, TypeVar, cast
from xml.etree import ElementTree as ET

from .xml import Element, SubElement, find, findall, findtext

A = TypeVar("A", bound="FilterRule")


@dataclass(frozen=True)
class FilterRule(ABC):
    """Filter rule."""

    name: str
    value: str

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        name = cast(str, findtext(element, "Name", True))
        value = cast(str, findtext(element, "Value", True))
        return cls(name, value)

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "FilterRule")
        SubElement(element, "Name", self.name)
        SubElement(element, "Value", self.value)
        return element


@dataclass(frozen=True)
class PrefixFilterRule(FilterRule):
    """Prefix filter rule."""

    def __init__(self, value: str):
        super().__init__(name="prefix", value=value)


@dataclass(frozen=True)
class SuffixFilterRule(FilterRule):
    """Suffix filter rule."""

    def __init__(self, value: str):
        super().__init__(name="suffix", value=value)


@dataclass(frozen=True)
class CommonConfig(ABC):
    """Common for cloud-function/queue/topic configuration."""

    events: list[str]
    config_id: Optional[str] = None
    prefix_filter_rule: Optional[PrefixFilterRule] = None
    suffix_filter_rule: Optional[SuffixFilterRule] = None

    def __post_init__(self):
        if not self.events:
            raise ValueError("events must be provided")

    @staticmethod
    def parsexml(
            element: ET.Element,
    ) -> tuple[
        list[str],
        Optional[str],
        Optional[PrefixFilterRule],
        Optional[SuffixFilterRule],
    ]:
        """Parse XML."""
        elements = findall(element, "Event")
        events = []
        for tag in elements:
            if tag.text is None:
                raise ValueError("missing value in XML tag 'Event'")
            events.append(tag.text)
        config_id = findtext(element, "Id")
        elem = find(element, "Filter")
        if elem is None:
            return events, config_id, None, None
        prefix_filter_rule = None
        suffix_filter_rule = None
        elem = cast(ET.Element, find(elem, "S3Key", True))
        elements = findall(elem, "FilterRule")
        for tag in elements:
            filter_rule = FilterRule.fromxml(tag)
            if filter_rule.name == "prefix":
                prefix_filter_rule = PrefixFilterRule(filter_rule.value)
            else:
                suffix_filter_rule = SuffixFilterRule(filter_rule.value)
        return events, config_id, prefix_filter_rule, suffix_filter_rule

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        for event in self.events:
            SubElement(element, "Event", event)
        if self.config_id is not None:
            SubElement(element, "Id", self.config_id)
        if self.prefix_filter_rule or self.suffix_filter_rule:
            rule = SubElement(element, "Filter")
            rule = SubElement(rule, "S3Key")
        if self.prefix_filter_rule:
            self.prefix_filter_rule.toxml(rule)
        if self.suffix_filter_rule:
            self.suffix_filter_rule.toxml(rule)
        return element


B = TypeVar("B", bound="CloudFuncConfig")


@dataclass(frozen=True)
class CloudFuncConfig(CommonConfig):
    """Cloud function configuration."""
    cloud_func: Optional[str] = None

    def __post_init__(self):
        if not self.cloud_func:
            raise ValueError("cloud function must be provided")

    @classmethod
    def fromxml(cls: Type[B], element: ET.Element) -> B:
        """Create new object with values from XML element."""
        cloud_func = cast(str, findtext(element, "CloudFunction", True))
        (events, config_id, prefix_filter_rule,
         suffix_filter_rule) = cls.parsexml(element)
        return cls(
            cloud_func=cloud_func,
            events=events,
            config_id=config_id,
            prefix_filter_rule=prefix_filter_rule,
            suffix_filter_rule=suffix_filter_rule,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "CloudFunctionConfiguration")
        SubElement(element, "CloudFunction", self.cloud_func)
        super().toxml(element)
        return element


C = TypeVar("C", bound="QueueConfig")


@dataclass(frozen=True)
class QueueConfig(CommonConfig):
    """Queue configuration."""
    queue: Optional[str] = None

    def __post_init__(self):
        if not self.queue:
            raise ValueError("queue must be provided")

    @classmethod
    def fromxml(cls: Type[C], element: ET.Element) -> C:
        """Create new object with values from XML element."""
        queue = cast(str, findtext(element, "Queue", True))
        (events, config_id, prefix_filter_rule,
         suffix_filter_rule) = cls.parsexml(element)
        return cls(
            queue=queue,
            events=events,
            config_id=config_id,
            prefix_filter_rule=prefix_filter_rule,
            suffix_filter_rule=suffix_filter_rule,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "QueueConfiguration")
        SubElement(element, "Queue", self.queue)
        super().toxml(element)
        return element


D = TypeVar("D", bound="TopicConfig")


@dataclass(frozen=True)
class TopicConfig(CommonConfig):
    """Get topic configuration."""
    topic: Optional[str] = None

    def __post_init__(self):
        if not self.topic:
            raise ValueError("topic must be provided")

    @classmethod
    def fromxml(cls: Type[D], element: ET.Element) -> D:
        """Create new object with values from XML element."""
        topic = cast(str, findtext(element, "Topic", True))
        (events, config_id, prefix_filter_rule,
         suffix_filter_rule) = cls.parsexml(element)
        return cls(
            topic=topic,
            events=events,
            config_id=config_id,
            prefix_filter_rule=prefix_filter_rule,
            suffix_filter_rule=suffix_filter_rule,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        if element is None:
            raise ValueError("element must be provided")
        element = SubElement(element, "TopicConfiguration")
        SubElement(element, "Topic", self.topic)
        super().toxml(element)
        return element


E = TypeVar("E", bound="NotificationConfig")


@dataclass(frozen=True)
class NotificationConfig:
    """Notification configuration."""
    cloud_func_config_list: list[CloudFuncConfig] = field(default_factory=list)
    queue_config_list: list[QueueConfig] = field(default_factory=list)
    topic_config_list: list[TopicConfig] = field(default_factory=list)

    @classmethod
    def fromxml(cls: Type[E], element: ET.Element) -> E:
        """Create new object with values from XML element."""
        elements = findall(element, "CloudFunctionConfiguration")
        cloud_func_config_list = []
        for tag in elements:
            cloud_func_config_list.append(CloudFuncConfig.fromxml(tag))
        elements = findall(element, "QueueConfiguration")
        queue_config_list = []
        for tag in elements:
            queue_config_list.append(QueueConfig.fromxml(tag))
        elements = findall(element, "TopicConfiguration")
        topic_config_list = []
        for tag in elements:
            topic_config_list.append(TopicConfig.fromxml(tag))
        return cls(
            cloud_func_config_list, queue_config_list, topic_config_list,
        )

    def toxml(self, element: Optional[ET.Element]) -> ET.Element:
        """Convert to XML."""
        element = Element("NotificationConfiguration")
        for cloud_func_config in self.cloud_func_config_list:
            cloud_func_config.toxml(element)
        for queue_config in self.queue_config_list:
            queue_config.toxml(element)
        for config in self.topic_config_list:
            config.toxml(element)
        return element
