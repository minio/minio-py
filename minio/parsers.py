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


def get_element_text(element, xpath, ns=_S3_NS):
    """
    Get element text for a given xpath.

    :param element: Element xml object.
    :param xpath: XML attribute inside the element.
    :param ns: Necessary namespace to look for.
    """
    return element.find(xpath, ns).text

def parse_multipart_upload_result(data):
    """
    Parser for complete multipart upload response.

    :param data: Response data for complete multipart upload.
    :return: :class:`MultipartUploadResult <MultipartUploadResult>`.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"CompleteMultipartUploadResult" XML is not parsable. '
                              'Message: {0}'.format(error.message))
    try:
        bucket_name = get_element_text(root, 's3:Bucket')
        object_name = get_element_text(root, 's3:Key')
        location = get_element_text(root, 's3:Location')
        etag = get_element_text(root, 's3:ETag')
        # Strip off quotes from beginning and the end.
        if etag.startswith('"') and etag.endswith('"'):
            etag = etag[len('"'):]
            etag = etag[:-len('"')]

        return MultipartUploadResult(bucket_name, object_name, location, etag)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Invalid XML provided for "CompleteMultipartUploadResult" '
                              'some fields are missing. Message: {0}'.format(error.message))

def parse_copy_object(bucket_name, object_name, data):
    """
    Parser for copy object response.

    :param data: Response data for copy object.
    :return: :class:`CopyObjectResult <CopyObjectResult>`
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"CopyObjectResult" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    try:
        etag = get_element_text(root, 's3:ETag')
        # Strip off quotes from beginning and the end.
        if etag.startswith('"') and etag.endswith('"'):
            etag = etag[len('"'):]
            etag = etag[:-len('"')]

        last_modified = _iso8601_to_localized_time(
            get_element_text(root, 's3:LastModified'))

        return CopyObjectResult(bucket_name, object_name, etag, last_modified)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Invalid XML provided for "CopyObjectResult" '
                              'some fields are missing. Message: {0}'.format(error.message))

def parse_list_buckets(data):
    """
    Parser for list buckets response.

    :param data: Response data for list buckets.
    :return: List of :class:`Bucket <Bucket>`.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListBucketsResult" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    bucket_list = []
    try:
        for buckets in root.findall('s3:Buckets', _S3_NS):
            for bucket in buckets:
                name = get_element_text(bucket, 's3:Name')
                creation_date = _iso8601_to_localized_time(get_element_text(bucket,
                                                                            's3:CreationDate'))
                bucket_list.append(Bucket(name, creation_date))
            return bucket_list
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Invalid XML provided for "ListBucketsResult" '
                              'some fields are missing. Message: {0}'.format(error.message))

def _parse_objects_from_xml_elts(bucket_name, contents, common_prefixes):
    """Internal function that extracts objects and common prefixes from
    list_objects responses.
    """
    objects = []
    for content in contents:
        key_elt = content.find('s3:Key', _S3_NS)
        object_name = urldecode(key_elt.text) if key_elt != None else None

        lmod_elt = content.find('s3:LastModified', _S3_NS)
        last_modified = (_iso8601_to_localized_time(lmod_elt.text)
                         if lmod_elt != None else None)

        etag_elt = content.find('s3:ETag', _S3_NS)
        etag = etag_elt.text.replace('"', '') if etag_elt != None else None

        size_elt = content.find('s3:Size', _S3_NS)
        size = int(size_elt.text) if size_elt != None else 0

        objects.append(Object(bucket_name, object_name, last_modified,
                              etag, size))

    object_dirs = []
    for dirs_elt in common_prefixes:
        # AWS docs are not clear if a CommonPrefixes element may have
        # multiple Prefix elements, so we try to parse more than one.
        for dir_elt in dirs_elt.findall('s3:Prefix', _S3_NS):
            object_name = urldecode(dir_elt.text)
            object_dirs.append(Object(bucket_name, object_name, None, '', 0,
                                      is_dir=True))

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
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListObjects" XML is not parsable. '
                              'Message: {0}'.format(error.message))
    objects = []

    is_truncated = root.find('s3:IsTruncated', _S3_NS).text == 'true'

    marker_elt = root.find('s3:NextMarker', _S3_NS)
    marker = urldecode(marker_elt.text) if marker_elt != None else None

    objects, object_dirs = _parse_objects_from_xml_elts(
        bucket_name,
        root.findall('s3:Contents', _S3_NS),
        root.findall('s3:CommonPrefixes', _S3_NS)
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
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListObjects" XML is not parsable. '
                              'Message: {0}'.format(error.message))
    objects = []

    # IsTruncated is always present in the response.
    is_truncated = root.find('s3:IsTruncated', _S3_NS).text == 'true'

    # NextContinuationToken may not be present.
    ct_elt = root.find('s3:NextContinuationToken', _S3_NS)
    continuation_token = ct_elt.text if ct_elt != None else None

    objects, object_dirs = _parse_objects_from_xml_elts(
        bucket_name,
        root.findall('s3:Contents', _S3_NS),
        root.findall('s3:CommonPrefixes', _S3_NS)
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
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListMultipartUploads" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    is_truncated = root.find('s3:IsTruncated', _S3_NS).text == 'true'

    next_key_text = root.findtext('s3:NextKeyMarker', None, _S3_NS)
    key_marker = (urldecode(next_key_text)
                  if next_key_text != None else None)

    upload_id_marker = root.findtext('s3:NextUploadIdMarker', None, _S3_NS)

    uploads = []
    for upload in root.findall('s3:Upload', _S3_NS):
        key_elt = upload.find('s3:Key', _S3_NS)
        object_name = urldecode(key_elt.text) if key_elt != None else None

        upload_id = upload.findtext('s3:UploadId', None, _S3_NS)

        initiated = _iso8601_to_localized_time(
            upload.findtext('s3:Initiated', None, _S3_NS)
        )
        uploads.append(
            IncompleteUpload(bucket_name, object_name, upload_id, initiated)
        )

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
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"ListParts" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    is_truncated = root.find('s3:IsTruncated', _S3_NS).text == 'true'
    part_marker = root.findtext('s3:NextPartNumberMarker', None, _S3_NS)
    parts = []
    for part in root.findall('s3:Part', _S3_NS):
        partnum_elt = part.find('s3:PartNumber', _S3_NS)
        part_number = int(partnum_elt.text) if partnum_elt != None else None

        etag_elt = part.find('s3:ETag', _S3_NS)
        etag = etag_elt.text.replace('"', '') if etag_elt != None else None

        last_modified = _iso8601_to_localized_time(
            part.findtext('s3:LastModified', None, _S3_NS)
        )

        size_elt = part.find('s3:Size', _S3_NS)
        size = int(size_elt.text) if size_elt != None else 0

        part = UploadPart(bucket_name, object_name,
                          upload_id, part_number,
                          etag, last_modified, size)
        parts.append(part)

    return parts, is_truncated, part_marker


def parse_new_multipart_upload(data):
    """
    Parser for new multipart upload response.

    :param data: Response data for new multipart upload.
    :return: Returns a upload id.
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"NewMultipartUpload" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    try:
        upload_id = get_element_text(root, 's3:UploadId')
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Missing "UploadId" XML attribute from "NewMultipartUpload". '
                              'Message: {0}'.format(error.message))
    return upload_id

def parse_location_constraint(data):
    """
    Parser for location constraint response.

    :param data: Response data for get bucket location.
    :return: Returns location of your bucket.
    """
    try:
        bucket_location = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"BucketLocationConstraint" XML is not parsable.'
                              ' Message: {0}'.format(error.message))

    try:
        location_constraint = bucket_location.text
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('Missing "LocationConstraint" XML attribute from '
                              '"BucketLocationConstraint". Message: {0}'.format(error.message))

    return location_constraint

def _iso8601_to_localized_time(date_string):
    """
    Convert iso8601 date string into UTC time.

    :param date_string: iso8601 formatted date string.
    :return: :class:`datetime.datetime`
    """
    if date_string is None:
        return None
    parsed_date = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    localized_time = pytz.utc.localize(parsed_date)
    return localized_time

def parse_get_bucket_notification(data):
    """
    Parser for a get_bucket_notification response from S3.

    :param data: Body of response from get_bucket_notification.
    :return: Returns bucket notification configuration
    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"GetBucketNotificationResult" XML is not parsable. '
                              'Message: {0}'.format(error.message))

    # perhaps we could ignore this condition?
    if root.tag != '{{{s3}}}NotificationConfiguration'.format(**_S3_NS):
        raise InvalidXMLError('"GetBucketNotificationresult" XML root is '
                              'invalid.')

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
    config = []
    stag = 's3:{}'.format(service_xml_tag)
    for service in data.findall(stag, _S3_NS):
        service_config = {}
        service_config['Id'] = service.find('s3:Id', _S3_NS).text
        arn_tag = 's3:{}'.format(
            NOTIFICATIONS_ARN_FIELDNAME_MAP[service_xml_tag]
        )
        service_config['Arn'] = service.find(arn_tag, _S3_NS).text
        service_config['Events'] = []
        for event in service.findall('s3:Event', _S3_NS):
            service_config['Events'].append(event.text)
        xml_filter_rule = service.find('s3:Filter', _S3_NS)
        if xml_filter_rule:
            xml_filter_rules = xml_filter_rule.find(
                's3:S3Key', _S3_NS).findall('s3:FilterRule', _S3_NS)
            filter_rules = []
            for xml_filter_rule in xml_filter_rules:
                filter_rules.append(
                    {
                        'Name': xml_filter_rule.find('s3:Name', _S3_NS),
                        'Value': xml_filter_rule.find('s3:Value', _S3_NS),
                    }
                )
            service_config['Filter'] = {
                'Key': {
                    'FilterRules': filter_rules
                }
            }
        config.append(service_config)
    if config:
        notifications[service_key] = config
    return notifications

def parse_multi_object_delete_response(data):
    """Parser for Multi-Object Delete API response.

    :param data: XML response body content from service.

    :return: Returns list of error objects for each delete object that
    had an error.

    """
    try:
        root = cElementTree.fromstring(data)
    except _ETREE_EXCEPTIONS as error:
        raise InvalidXMLError('"MultiObjectDelete" XML is not parsable. '
                              'Message: {}'.format(error.message))

    errs_result = []
    for contents in root:
        if contents.tag == "Error":
            key = contents.find('Key').text
            err_code = contents.find('Code').text
            err_message = contents.find('Message').text
            errs_result.append(
                MultiDeleteError(key, err_code, err_message)
            )

    return errs_result
