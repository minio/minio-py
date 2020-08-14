# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017, 2018, 2019 MinIO, Inc.
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
minio.xml_marshal
~~~~~~~~~~~~~~~

This module contains the simple wrappers for XML marshaller's.

:copyright: (c) 2015 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import

import io
from collections import defaultdict
from xml.etree import ElementTree as ET

from .compat import basestring

_S3_NAMESPACE = 'http://s3.amazonaws.com/doc/2006-03-01/'


def Element(tag, with_namespace=False):  # pylint: disable=invalid-name
    """Create ElementTree.Element with tag and namespace."""
    if with_namespace:
        return ET.Element(tag, {'xmlns': _S3_NAMESPACE})
    return ET.Element(tag)


def SubElement(parent, tag, text=None):  # pylint: disable=invalid-name
    """Create ElementTree.SubElement on parent with tag and text."""
    element = ET.SubElement(parent, tag)
    if text is not None:
        element.text = text
    return element


def _get_xml_data(element):
    """Get XML data of ElementTree.Element."""
    data = io.BytesIO()
    ET.ElementTree(element).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()


def _etree_to_dict(elem):
    """Converts ElementTree object to dict."""
    ns = '{' + _S3_NAMESPACE + '}'  # pylint: disable=invalid-name
    elem.tag = elem.tag.replace(ns, '')

    d = {elem.tag: {} if elem.attrib else None}  # pylint: disable=invalid-name
    children = list(elem)
    if children:
        dd = defaultdict(list)  # pylint: disable=invalid-name
        is_rule = children[0].tag.replace(ns, "") == "Rule"
        # pylint: disable=invalid-name
        for dc in map(_etree_to_dict, children):
            for k, v in dc.items():  # pylint: disable=invalid-name
                dd[k].append([v] if is_rule else v)
        # pylint: disable=invalid-name
        d = {elem.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
    if elem.attrib:
        d[elem.tag].update(('@' + k, v) for k, v in elem.attrib.items())
    if elem.text:
        text = elem.text.strip()
        if children or elem.attrib:
            if text:
                d[elem.tag]['#text'] = text
        else:
            d[elem.tag] = text
    return d


def xml_to_dict(in_xml):
    """Convert XML to dict."""
    elem = ET.XML(in_xml)
    return _etree_to_dict(elem)


def xml_marshal_bucket_encryption(rules):
    """Encode bucket encryption to XML."""

    root = Element('ServerSideEncryptionConfiguration')

    if rules:
        # As server supports only one rule, the first rule is taken due to
        # no validation is done at server side.
        apply_element = SubElement(SubElement(root, 'Rule'),
                                   'ApplyServerSideEncryptionByDefault')
        SubElement(apply_element, 'SSEAlgorithm',
                   rules[0]['ApplyServerSideEncryptionByDefault'].get(
                       'SSEAlgorithm', 'AES256'))
        kms_text = rules[0]['ApplyServerSideEncryptionByDefault'].get(
            'KMSMasterKeyID')
        if kms_text:
            SubElement(apply_element, 'KMSMasterKeyID', kms_text)

    return _get_xml_data(root)


def xml_marshal_bucket_constraint(region):
    """
    Marshal's bucket constraint based on *region*.

    :param region: Region name of a given bucket.
    :return: Marshalled XML data.
    """
    root = Element('CreateBucketConfiguration', with_namespace=True)
    SubElement(root, 'LocationConstraint', region)
    return _get_xml_data(root)


def xml_marshal_select(req):
    """Encode select request to XML."""

    def bool_to_str(value):
        return "true" if value else "false"

    root = Element("SelectObjectContentRequest")
    SubElement(root, "Expression", req.expression)
    SubElement(root, "ExpressionType", "SQL")

    input_serialization = SubElement(root, "InputSerialization")
    SubElement(
        input_serialization,
        "CompressionType",
        req.input_serialization.compression_type,
    )

    if req.input_serialization.csv:
        csv = SubElement(input_serialization, "CSV")
        SubElement(
            csv,
            "FileHeaderInfo",
            req.input_serialization.csv.file_header_info,
        )
        SubElement(
            csv,
            "RecordDelimiter",
            req.input_serialization.csv.record_delimiter,
        )
        SubElement(
            csv, "FieldDelimiter", req.input_serialization.csv.field_delimiter,
        )
        SubElement(
            csv, "QuoteCharacter", req.input_serialization.csv.quote_character,
        )
        SubElement(
            csv,
            "QuoteEscapeCharacter",
            req.input_serialization.csv.quote_escape_character,
        )
        SubElement(csv, "Comments", req.input_serialization.csv.comments)
        SubElement(
            csv,
            "AllowQuotedRecordDelimiter",
            bool_to_str(
                req.input_serialization.csv.allow_quoted_record_delimiter,
            ),
        )

    if req.input_serialization.json:
        SubElement(
            SubElement(input_serialization, "JSON"),
            "Type",
            req.input_serialization.json.json_type,
        )

    if req.input_serialization.parquet:
        SubElement(input_serialization, "Parquet")

    output_serialization = SubElement(root, "OutputSerialization")
    if req.output_serialization.csv:
        csv = SubElement(output_serialization, "CSV")
        SubElement(
            csv,
            "QuoteFields",
            req.output_serialization.csv.quote_fields,
        )
        SubElement(
            csv,
            "RecordDelimiter",
            req.output_serialization.csv.record_delimiter,
        )
        SubElement(
            csv,
            "FieldDelimiter",
            req.output_serialization.csv.field_delimiter,
        )
        SubElement(
            csv,
            "QuoteCharacter",
            req.output_serialization.csv.quote_character,
        )
        SubElement(
            csv,
            "QuoteEscapeCharacter",
            req.output_serialization.csv.quote_escape_character,
        )

    if req.output_serialization.json:
        SubElement(
            SubElement(output_serialization, "JSON"),
            "RecordDelimiter",
            req.output_serialization.json.record_delimiter,
        )

    SubElement(
        SubElement(root, "RequestProgress"),
        "Enabled",
        bool_to_str(req.request_progress.enabled),
    )

    return _get_xml_data(root)


def marshal_complete_multipart(uploaded_parts):
    """
    Marshal's complete multipart upload request based on *uploaded_parts*.

    :param uploaded_parts: List of all uploaded parts, ordered by part number.
    :return: Marshalled XML data.
    """
    root = Element('CompleteMultipartUpload', with_namespace=True)
    for uploaded_part in uploaded_parts:
        part = SubElement(root, 'Part')
        SubElement(part, 'PartNumber', str(uploaded_part.part_number))
        SubElement(part, 'ETag', '"' + uploaded_part.etag + '"')

    return _get_xml_data(root)


def marshal_bucket_notifications(notifications):
    """
    Marshals the notifications structure for sending to S3 compatible storage

    :param notifications: Dictionary with following structure:

    {
        'TopicConfigurations': [
            {
                'Id': 'string',
                'Arn': 'string',
                'Events': [
                    's3:ReducedRedundancyLostObject'|'s3:ObjectCreated:*'|
                    's3:ObjectCreated:Put'|'s3:ObjectCreated:Post'|
                    's3:ObjectCreated:Copy'|
                    's3:ObjectCreated:CompleteMultipartUpload'|
                    's3:ObjectRemoved:*'|'s3:ObjectRemoved:Delete'|
                    's3:ObjectRemoved:DeleteMarkerCreated',
                ],
                'Filter': {
                    'Key': {
                        'FilterRules': [
                            {
                                'Name': 'prefix'|'suffix',
                                'Value': 'string'
                            },
                        ]
                    }
                }
            },
        ],
        'QueueConfigurations': [
            {
                'Id': 'string',
                'Arn': 'string',
                'Events': [
                    's3:ReducedRedundancyLostObject'|'s3:ObjectCreated:*'|
                    's3:ObjectCreated:Put'|'s3:ObjectCreated:Post'|
                    's3:ObjectCreated:Copy'|
                    's3:ObjectCreated:CompleteMultipartUpload'|
                    's3:ObjectRemoved:*'|'s3:ObjectRemoved:Delete'|
                    's3:ObjectRemoved:DeleteMarkerCreated',
                ],
                'Filter': {
                    'Key': {
                        'FilterRules': [
                            {
                                'Name': 'prefix'|'suffix',
                                'Value': 'string'
                            },
                        ]
                    }
                }
            },
        ],
        'CloudFunctionConfigurations': [
            {
                'Id': 'string',
                'Arn': 'string',
                'Events': [
                    's3:ReducedRedundancyLostObject'|'s3:ObjectCreated:*'|
                    's3:ObjectCreated:Put'|'s3:ObjectCreated:Post'|
                    's3:ObjectCreated:Copy'|
                    's3:ObjectCreated:CompleteMultipartUpload'|
                    's3:ObjectRemoved:*'|'s3:ObjectRemoved:Delete'|
                    's3:ObjectRemoved:DeleteMarkerCreated',
                ],
                'Filter': {
                    'Key': {
                        'FilterRules': [
                            {
                                'Name': 'prefix'|'suffix',
                                'Value': 'string'
                            },
                        ]
                    }
                }
            },
        ]
    }

    :return: Marshalled XML data
    """
    root = Element('NotificationConfiguration', with_namespace=True)
    _add_notification_config_to_xml(
        root,
        'TopicConfiguration',
        notifications.get('TopicConfigurations', [])
    )
    _add_notification_config_to_xml(
        root,
        'QueueConfiguration',
        notifications.get('QueueConfigurations', [])
    )
    _add_notification_config_to_xml(
        root,
        'CloudFunctionConfiguration',
        notifications.get('CloudFunctionConfigurations', [])
    )

    return _get_xml_data(root)


NOTIFICATIONS_ARN_FIELDNAME_MAP = {
    'TopicConfiguration': 'Topic',
    'QueueConfiguration': 'Queue',
    'CloudFunctionConfiguration': 'CloudFunction',
}


def _add_notification_config_to_xml(node, element_name, configs):
    """
    Internal function that builds the XML sub-structure for a given
    kind of notification configuration.

    """
    for config in configs:
        config_node = SubElement(node, element_name)

        if 'Id' in config:
            SubElement(config_node, 'Id', config['Id'])

        SubElement(config_node, NOTIFICATIONS_ARN_FIELDNAME_MAP[element_name],
                   config['Arn'])

        for event in config['Events']:
            SubElement(config_node, 'Event', event)

        filter_rules = config.get('Filter', {}).get(
            'Key', {}).get('FilterRules', [])
        if filter_rules:
            s3key_node = SubElement(SubElement(config_node, 'Filter'), 'S3Key')
            for filter_rule in filter_rules:
                filter_rule_node = SubElement(s3key_node, 'FilterRule')
                SubElement(filter_rule_node, 'Name', filter_rule['Name'])
                SubElement(filter_rule_node, 'Value', filter_rule['Value'])
    return node


def xml_marshal_delete_objects(keys):
    """
    Marshal Multi-Object Delete request body from object names.

    :param object_names: List of object keys to be deleted.
    :return: Serialized XML string for multi-object delete request body.
    """
    root = Element('Delete')

    # use quiet mode in the request - this causes the S3 Server to
    # limit its response to only object keys that had errors during
    # the delete operation.
    SubElement(root, 'Quiet', "true")

    # add each object to the request.
    for key in keys:
        version_id = None
        if not isinstance(key, basestring):
            version_id = key[1]
            key = key[0]

        element = SubElement(root, "Object")
        SubElement(element, "Key", key)
        if version_id:
            SubElement(element, "VersionId", version_id)

    return _get_xml_data(root)
