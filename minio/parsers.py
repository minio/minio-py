# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

# standard.
from xml.etree import cElementTree
from xml.etree.cElementTree import ParseError

from datetime import datetime

# dependencies.
import pytz

# minio specific.
from .error import (InvalidXMLError, MultiDeleteError)
from .compat import urldecode
from .definitions import (Object, Bucket, IncompleteUpload,
                          UploadPart, MultipartUploadResult,
                          CopyObjectResult)
from .xml_marshal import (NOTIFICATIONS_ARN_FIELDNAME_MAP)


if hasattr(cElementTree, 'ParseError'):
    _ETREE_EXCEPTIONS = (ParseError, AttributeError, ValueError, TypeError)
else:
    _ETREE_EXCEPTIONS = (SyntaxError, AttributeError, ValueError, TypeError)

_S3_NS = {'s3' : 'http://s3.amazonaws.com/doc/2006-03-01/'}


class S3Element(object):
    """S3 aware XML parsing class. Wraps a root element name and
    cElementTree.Element instance. Provides S3 namespace aware parsing
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
            return cls(root_name, cElementTree.fromstring(data))
        except _ETREE_EXCEPTIONS as error:
            raise InvalidXMLError(
                '"{}" XML is not parsable. Message: {}'.format(
                    root_name, error.message
                )
            )

    def findall(self, name):
        """Similar to ElementTree.Element.findall()

        """
        return [
            S3Element(self.root_name, elem)
            for elem in self.element.findall('s3:{}'.format(name), _S3_NS)
        ]

    def find(self, name):
        """Similar to ElementTree.Element.find()

        """
        elt = self.element.find('s3:{}'.format(name), _S3_NS)
        return S3Element(self.root_name, elt) if elt is not None else None

    def get_child_text(self, name, strict=True):
        """Extract text of a child element. If strict, and child element is
        not present, raises InvalidXMLError and otherwise returns
        None.

        """
        if strict:
            try:
                return self.element.find('s3:{}'.format(name), _S3_NS).text
            except _ETREE_EXCEPTIONS as error:
                raise InvalidXMLError(
                    ('Invalid XML provided for "{}" - erroring tag <{}>. '
                     'Message: {}').format(self.root_name, name, error.message)
                )
        else:
            return self.element.findtext('s3:{}'.format(name), None, _S3_NS)

    def get_urldecoded_elem_text(self, name, strict=True):
        """Like self.get_child_text(), but also performs urldecode() on the
        result.

        """
        text = self.get_child_text(name, strict)
        # strictness is already enforced above.
        return urldecode(text) if text is not None else None

    def get_etag_elem(self):
        """Fetches an 'ETag' child element suitably processed.

        """
        return self.get_child_text('ETag').replace('"', '')

    def get_int_elem(self, name):
        """Fetches an integer type XML child element by name.

        """
        return int(self.get_child_text(name))

    def get_localized_time_elem(self, name):
        """Parse a time XML child element.

        """
        return _iso8601_to_localized_time(self.get_child_text(name))

    def text(self):
        """Fetch the current node's text

        """
        return self.element.text


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

def parse_copy_object(bucket_name, object_name, data):
    """
    Parser for copy object response.

    :param data: Response data for copy object.
    :return: :class:`CopyObjectResult <CopyObjectResult>`
    """
    root = S3Element.fromstring('CopyObjectResult', data)

    return CopyObjectResult(
        bucket_name, object_name,
        root.get_etag_elem(),
        root.get_localized_time_elem('LastModified')
    )

def parse_list_buckets(data):
    """
    Parser for list buckets response.

    :param data: Response data for list buckets.
    :return: List of :class:`Bucket <Bucket>`.
    """
    root = S3Element.fromstring('ListBucketsResult', data)

    return [
        Bucket(bucket.get_child_text('Name'),
               bucket.get_localized_time_elem('CreationDate'))
        for buckets in root.findall('Buckets')
        for bucket in buckets.findall('Bucket')
    ]

def _parse_objects_from_xml_elts(bucket_name, contents, common_prefixes):
    """Internal function that extracts objects and common prefixes from
    list_objects responses.
    """
    objects = [
        Object(bucket_name,
               content.get_urldecoded_elem_text('Key'),
               content.get_localized_time_elem('LastModified'),
               content.get_etag_elem(),
               content.get_int_elem('Size'))
        for content in contents
    ]

    object_dirs = [
        Object(bucket_name, urldecode(dir_elt.text()), None, '',
               0, is_dir=True)
        for dirs_elt in common_prefixes
        for dir_elt in dirs_elt
    ]

    return objects, object_dirs

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
    objects, object_dirs = _parse_objects_from_xml_elts(
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
    objects, object_dirs = _parse_objects_from_xml_elts(
        bucket_name,
        root.findall('Contents'),
        root.findall('CommonPrefixes')
    )

    return objects + object_dirs, is_truncated, continuation_token

def parse_list_multipart_uploads(data, bucket_name):
    """
    Parser for list multipart uploads response.

    :param data: Response data for list multipart uploads.
    :param bucket_name: Response for the bucket.
    :return: Replies back four distinctive components.
       - List of :class:`IncompleteUpload <IncompleteUpload>`
       - True if list is truncated, False otherwise.
       - Object name marker for the next request.
       - Upload id marker for the next request.
    """
    root = S3Element.fromstring('ListMultipartUploadsResult', data)

    is_truncated = root.get_child_text('IsTruncated').lower() == 'true'
    key_marker = root.get_urldecoded_elem_text('NextKeyMarker', strict=False)
    upload_id_marker = root.get_child_text('NextUploadIdMarker', strict=False)
    uploads = [
        IncompleteUpload(bucket_name,
                         upload.get_urldecoded_elem_text('Key'),
                         upload.get_child_text('UploadId'),
                         upload.get_localized_time_elem('Initiated'))
        for upload in root.findall('Upload')
    ]

    return uploads, is_truncated, key_marker, upload_id_marker


def parse_list_parts(data, bucket_name, object_name, upload_id):
    """
    Parser for list parts response.

    :param data: Response data for list parts.
    :param bucket_name: Response for the bucket.
    :param object_name: Response for the object.
    :param upload_id: Upload id of object name for
       the active multipart session.
    :return: Replies back three distinctive components.
       - List of :class:`UploadPart <UploadPart>`.
       - True if list is truncated, False otherwise.
       - Next part marker for the next request if the
         list was truncated.
    """
    root = S3Element.fromstring('ListPartsResult', data)

    is_truncated = root.get_child_text('IsTruncated').lower() == 'true'
    part_marker = root.get_child_text('NextPartNumberMarker', strict=False)
    parts = [
        UploadPart(bucket_name, object_name, upload_id,
                   part.get_int_elem('PartNumber'),
                   part.get_etag_elem(),
                   part.get_localized_time_elem('LastModified'),
                   part.get_int_elem('Size'))
        for part in root.findall('Part')
    ]

    return parts, is_truncated, part_marker

def parse_new_multipart_upload(data):
    """
    Parser for new multipart upload response.

    :param data: Response data for new multipart upload.
    :return: Returns a upload id.
    """
    root = S3Element.fromstring('NewMultipartUploadResult', data)
    return root.get_child_text('UploadId')

def parse_location_constraint(data):
    """
    Parser for location constraint response.

    :param data: Response data for get bucket location.
    :return: Returns location of your bucket.
    """
    root = S3Element.fromstring('BucketLocationConstraintResult', data)
    return root.text()

def _iso8601_to_localized_time(date_string):
    """
    Convert iso8601 date string into UTC time.

    :param date_string: iso8601 formatted date string.
    :return: :class:`datetime.datetime`
    """
    parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    localized_time = pytz.utc.localize(parsed_date)
    return localized_time

def parse_get_bucket_notification(data):
    """
    Parser for a get_bucket_notification response from S3.

    :param data: Body of response from get_bucket_notification.
    :return: Returns bucket notification configuration
    """
    root = S3Element.fromstring('GetBucketNotificationResult', data)

    notifications = _parse_add_notifying_service_config(
        root, {},
        'TopicConfigurations', 'TopicConfiguration'
    )
    notifications = _parse_add_notifying_service_config(
        root, notifications,
        'QueueConfigurations', 'QueueConfiguration'
    )
    notifications = _parse_add_notifying_service_config(
        root, notifications,
        'CloudFunctionConfigurations', 'CloudFunctionConfiguration'
    )

    return notifications

def _parse_add_notifying_service_config(data, notifications, service_key,
                                        service_xml_tag):

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

def parse_multi_object_delete_response(data):
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
