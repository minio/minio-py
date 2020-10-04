# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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
minio.parsers
~~~~~~~~~~~~~~~~~~~

This module contains core API parsers.

:copyright: (c) 2015 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from datetime import timezone
from urllib.parse import unquote
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

from .definitions import (ListMultipartUploadsResult, ListPartsResult,
                          MultipartUploadResult, Object)
# minio specific.
from .error import MultiDeleteError, S3Error
from .helpers import strptime_rfc3339
from .xml_marshal import NOTIFICATIONS_ARN_FIELDNAME_MAP

# dependencies.


_XML_NS = {
    's3': 'http://s3.amazonaws.com/doc/2006-03-01/',
}


class S3Element:
    """S3 aware XML parsing class. Wraps a root element name and
    ElementTree.Element instance. Provides S3 namespace aware parsing
    functions.

    """

    def __init__(self, root_name, element):
        self.root_name = root_name
        self.element = element

    @classmethod
    def fromstring(cls, root_name, data):
        """Initialize S3Element from name and XML string data.

        :param name: Name for XML data. Used in XML errors.
        :param data: string data to be parsed.
        :return: Returns an S3Element.
        """
        try:
            return cls(root_name, ElementTree.fromstring(data.strip()))
        except (ParseError, AttributeError, ValueError, TypeError) as exc:
            raise ValueError(
                '"{}" XML is not parsable.'.format(root_name),
            ) from exc

    def findall(self, name):
        """Similar to ElementTree.Element.findall()

        """
        return [
            S3Element(self.root_name, elem)
            for elem in self.element.findall('s3:{}'.format(name), _XML_NS)
        ]

    def find(self, name):
        """Similar to ElementTree.Element.find()

        """
        elt = self.element.find('s3:{}'.format(name), _XML_NS)
        return S3Element(self.root_name, elt) if elt else None

    def get_child_text(self, name, strict=True):
        """Extract text of a child element. If strict, and child element is
        not present, raises ValueError and otherwise returns
        None.

        """
        if strict:
            try:
                return self.element.find('s3:{}'.format(name), _XML_NS).text
            except (ParseError, AttributeError, ValueError, TypeError) as exc:
                raise ValueError(
                    (
                        'Invalid XML provided for "{}" - erroring tag <{}>'
                    ).format(self.root_name, name),
                ) from exc
        else:
            return self.element.findtext('s3:{}'.format(name), None, _XML_NS)

    def get_urldecoded_elem_text(self, name, strict=True):
        """Like self.get_child_text(), but also performs urldecode() on the
        result.

        """
        text = self.get_child_text(name, strict)
        # strictness is already enforced above.
        return unquote(text) if text is not None else None

    def get_etag_elem(self, strict=True):
        """Fetches an 'ETag' child element suitably processed.

        """
        return self.get_child_text('ETag', strict).replace('"', '')

    def get_int_elem(self, name):
        """Fetches an integer type XML child element by name.

        """
        return int(self.get_child_text(name))

    def get_time_elem(self, name):
        """Parse a time XML child element.

        """
        return strptime_rfc3339(
            self.get_child_text(name),
        ).replace(tzinfo=timezone.utc)

    def text(self):
        """Fetch the current node's text

        """
        return self.element.text

    def is_dir(self):
        """Returns True if the object is a dir
        ie, if an object name has `/` suffixed.

        """
        text = self.get_child_text('Key')
        return text.endswith("/")


def parse_error_response(response):
    """Parser for S3 error response."""
    element = ElementTree.fromstring(response.data.decode())

    def _get_text(name):
        return (
            element.find(name).text if element.find(name) is not None else None
        )

    return S3Error(
        _get_text("Code"),
        _get_text("Message"),
        _get_text("Resource"),
        _get_text("RequestId"),
        _get_text("HostId"),
        bucket_name=_get_text("BucketName"),
        object_name=_get_text("Key"),
        response=response,
    )


def parse_multipart_upload_result(data):
    """
    Parser for complete multipart upload response.

    :param data: Response data for complete multipart upload.
    :return: :class:`MultipartUploadResult <MultipartUploadResult>`.
    """
    root = S3Element.fromstring('CompleteMultipartUploadResult', data)

    return MultipartUploadResult(
        root.get_child_text('Bucket'),
        root.get_child_text('Key'),
        root.get_child_text('Location'),
        root.get_etag_elem()
    )


def _parse_objects_from_xml_elts(bucket_name, contents, common_prefixes,
                                 delete_markers=()):
    """Internal function that extracts objects and common prefixes from
    list_objects responses.
    """
    objects = [
        Object(
            bucket_name,
            content.get_child_text("Key"),
            last_modified=content.get_time_elem("LastModified"),
            etag=content.get_etag_elem(strict=False),
            size=content.get_int_elem("Size"),
            is_dir=content.is_dir(),
            version_id=content.get_child_text("VersionId", strict=False),
            is_latest=content.get_child_text("IsLatest", strict=False),
            storage_class=content.get_child_text("StorageClass", strict=False),
            owner_id=(
                content.find("Owner").get_child_text("ID", strict=False)
                if content.find("Owner") else None
            ),
            owner_name=(
                content.find("Owner").get_child_text(
                    "DisplayName", strict=False,
                ) if content.find("Owner") else None
            ),
        ) for content in contents
    ]

    object_dirs = [
        Object(bucket_name, dir_elt.text(), is_dir=True)
        for dirs_elt in common_prefixes
        for dir_elt in dirs_elt.findall('Prefix')
    ]

    markers = [
        Object(
            bucket_name,
            content.get_child_text("Key"),
            last_modified=content.get_time_elem("LastModified"),
            is_dir=content.is_dir(),
            version_id=content.get_child_text("VersionId", strict=False),
            is_latest=content.get_child_text("IsLatest", strict=False),
            owner_id=(
                content.find("Owner").get_child_text("ID", strict=False)
                if content.find("Owner") else None
            ),
            owner_name=(
                content.find("Owner").get_child_text(
                    "DisplayName", strict=False,
                ) if content.find("Owner") else None
            ),
            delete_marker=True,
        ) for content in delete_markers
    ]

    return objects, object_dirs, markers


def parse_list_objects(data, bucket_name):
    """
    Parser for list objects response.

    :param data: Response data for list objects.
    :param bucket_name: Response for the bucket.
    :return: Replies back three distinctive components.
       - List of :class:`Object <Object>`
       - True if list is truncated, False otherwise.
       - Object name marker for the next request.
    """
    root = S3Element.fromstring('ListObjectResult', data)

    is_truncated = root.get_child_text('IsTruncated').lower() == 'true'
    # NextMarker element need not be present.
    marker = root.get_urldecoded_elem_text('NextMarker', strict=False)
    objects, object_dirs, _ = _parse_objects_from_xml_elts(
        bucket_name,
        root.findall('Contents'),
        root.findall('CommonPrefixes')
    )

    if is_truncated and marker is None:
        marker = objects[-1].object_name

    return objects + object_dirs, is_truncated, marker


def parse_list_objects_v2(data, bucket_name):
    """
    Parser for list objects version 2 response.

    :param data: Response data for list objects.
    :param bucket_name: Response for the bucket.
    :return: Returns three distinct components:
       - List of :class:`Object <Object>`
       - True if list is truncated, False otherwise.
       - Continuation Token for the next request.
    """
    root = S3Element.fromstring('ListObjectV2Result', data)

    is_truncated = root.get_child_text('IsTruncated').lower() == 'true'
    # NextContinuationToken may not be present.
    continuation_token = root.get_child_text('NextContinuationToken',
                                             strict=False)
    objects, object_dirs, _ = _parse_objects_from_xml_elts(
        bucket_name,
        root.findall('Contents'),
        root.findall('CommonPrefixes')
    )

    return objects + object_dirs, is_truncated, continuation_token


def parse_list_object_versions(data, bucket_name):
    """
    Parser for list object versions response.

    :param data: Response data for list objects.
    :param bucket_name: Response for the bucket.
    :return: Returns three distinct components:
       - List of :class:`Object <Object>`
       - True if list is truncated, False otherwise.
       - Continuation Token for the next request.
    """
    root = S3Element.fromstring("ListVersionsResult", data)

    is_truncated = root.get_child_text("IsTruncated").lower() == "true"

    key_marker = root.get_urldecoded_elem_text("NextKeyMarker", strict=False)
    version_id_marker = root.get_urldecoded_elem_text(
        "NextVersionIdMarker",
        strict=False,
    )

    objects, object_dirs, delete_markers = _parse_objects_from_xml_elts(
        bucket_name,
        root.findall("Version"),
        root.findall("CommonPrefixes"),
        root.findall("DeleteMarker"),
    )

    return (
        objects + object_dirs + delete_markers,
        is_truncated,
        key_marker,
        version_id_marker,
    )


def parse_new_multipart_upload(data):
    """
    Parser for new multipart upload response.

    :param data: Response data for new multipart upload.
    :return: Returns a upload id.
    """
    root = S3Element.fromstring('InitiateMultipartUploadResult', data)
    return root.get_child_text('UploadId')


def parse_get_bucket_notification(data):
    """
    Parser for a get_bucket_notification response from S3.

    :param data: Body of response from get_bucket_notification.
    :return: Returns bucket notification configuration
    """
    root = S3Element.fromstring('GetBucketNotificationResult', data)

    notifications = _add_notifying_service_config(
        root, {},
        'TopicConfigurations', 'TopicConfiguration'
    )
    notifications = _add_notifying_service_config(
        root, notifications,
        'QueueConfigurations', 'QueueConfiguration'
    )
    notifications = _add_notifying_service_config(
        root, notifications,
        'CloudFunctionConfigurations', 'CloudFunctionConfiguration'
    )

    return notifications


def _add_notifying_service_config(data, notifications, service_key,
                                  service_xml_tag):
    """Add service configuration in notification."""

    arn_elt_name = NOTIFICATIONS_ARN_FIELDNAME_MAP[service_xml_tag]
    config = []
    for service in data.findall(service_xml_tag):
        config_item = {}
        config_item['Id'] = service.get_child_text('Id')
        config_item['Arn'] = service.get_child_text(arn_elt_name)
        config_item['Events'] = [
            event.text() for event in service.findall('Event')
        ]
        filter_terms = [
            {
                'Key': {
                    'FilterRules': [
                        {
                            'Name': xml_filter_rule.get_child_text('Name'),
                            'Value': xml_filter_rule.get_child_text('Value'),
                        }
                        for xml_filter_rule in xml_filter_rules.findall(
                            './S3Key/FilterRule')
                    ]
                }
            }
            for xml_filter_rules in service.findall('Filter')
        ]
        if len(filter_terms) > 0:
            config_item['Filter'] = filter_terms
        config.append(config_item)

    if len(config) > 0:
        notifications[service_key] = config

    return notifications


def parse_multi_delete_response(data):
    """Parser for Multi-Object Delete API response.

    :param data: XML response body content from service.

    :return: Returns list of error objects for each delete object that
    had an error.

    """
    root = S3Element.fromstring('MultiObjectDeleteResult', data)
    return [
        MultiDeleteError(errtag.get_child_text('Key'),
                         errtag.get_child_text('Code'),
                         errtag.get_child_text('Message'))
        for errtag in root.findall('Error')
    ]


def parse_list_multipart_uploads(data):
    """Parse ListMultipartUploads API resppnse XML."""
    return ListMultipartUploadsResult(
        S3Element.fromstring("ListMultipartUploadsResult", data),
    )


def parse_list_parts(data):
    """Parse ListParts API resppnse XML."""
    return ListPartsResult(S3Element.fromstring("ListPartsResult", data))
