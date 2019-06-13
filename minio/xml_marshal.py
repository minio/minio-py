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

from xml.etree import ElementTree as s3_xml

_S3_NAMESPACE = 'http://s3.amazonaws.com/doc/2006-03-01/'


def xml_marshal_bucket_constraint(region):
    """
    Marshal's bucket constraint based on *region*.

    :param region: Region name of a given bucket.
    :return: Marshalled XML data.
    """
    root = s3_xml.Element('CreateBucketConfiguration', {'xmlns': _S3_NAMESPACE})
    location_constraint = s3_xml.SubElement(root, 'LocationConstraint')
    location_constraint.text = region
    data = io.BytesIO()
    s3_xml.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()


def xml_marshal_select(opts):
    root = s3_xml.Element('SelectObjectContentRequest')
    expression = s3_xml.SubElement(root, 'Expression')
    expression.text = opts.expression
    expression_type = s3_xml.SubElement(root, 'ExpressionType')
    expression_type.text = 'SQL'
    input_serialization = s3_xml.SubElement(root, 'InputSerialization')

    if opts.in_ser.csv_input is not None:
        compression_type = s3_xml.SubElement(input_serialization, 'CompressionType')
        compression_type.text = opts.in_ser.compression_type
        csv = s3_xml.SubElement(input_serialization, 'CSV')
        file_header_info = s3_xml.SubElement(csv, 'FileHeaderInfo')
        file_header_info.text = opts.in_ser.csv_input.FileHeaderInfo
        record_delimiter = s3_xml.SubElement(csv, 'RecordDelimiter')
        record_delimiter.text = opts.in_ser.csv_input.RecordDelimiter
        field_delimiter = s3_xml.SubElement(csv, 'FieldDelimiter')
        field_delimiter.text = opts.in_ser.csv_input.FieldDelimiter
        quote_character = s3_xml.SubElement(csv, 'QuoteCharacter')
        quote_character.text = opts.in_ser.csv_input.QuoteCharacter
        quote_escape_character = s3_xml.SubElement(csv, 'QuoteEscapeCharacter')
        quote_escape_character.text = opts.in_ser.csv_input.QuoteEscapeCharacter
        comments = s3_xml.SubElement(csv, 'Comments')
        comments.text = opts.in_ser.csv_input.Comments
        allow_quoted_record_delimiter = s3_xml.SubElement(csv, 'AllowQuotedRecordDelimiter')
        allow_quoted_record_delimiter.text = opts.in_ser.csv_input.AllowQuotedRecordDelimiter.lower()

    if opts.in_ser.json_input is not None:
        compression_type = s3_xml.SubElement(input_serialization, 'CompressionType')
        compression_type.text = opts.in_ser.compression_type
        json = s3_xml.SubElement(input_serialization, 'JSON')
        type_input = s3_xml.SubElement(json, 'Type')
        type_input.text = opts.in_ser.json_input.Type

    if opts.in_ser.parquet_input is not None:
        compression_type = s3_xml.SubElement(input_serialization, 'CompressionType')
        compression_type.text = opts.in_ser.compression_type
        s3_xml.SubElement(input_serialization, 'Parquet')

    output_serialization = s3_xml.SubElement(root, 'OutputSerialization')
    if opts.out_ser.csv_output is not None:
        csv = s3_xml.SubElement(output_serialization, 'CSV')
        quote_field = s3_xml.SubElement(csv, 'QuoteFields')
        quote_field.text = opts.out_ser.csv_output.QuoteFields
        record_delimiter = s3_xml.SubElement(csv, 'RecordDelimiter')
        record_delimiter.text = opts.out_ser.csv_output.RecordDelimiter
        field_delimiter = s3_xml.SubElement(csv, 'FieldDelimiter')
        field_delimiter.text = opts.out_ser.csv_output.FieldDelimiter
        quote_character = s3_xml.SubElement(csv, 'QuoteCharacter')
        quote_character.text = opts.out_ser.csv_output.QuoteCharacter
        quote_escape_character = s3_xml.SubElement(csv, 'QuoteEscapeCharacter')
        quote_escape_character.text = opts.out_ser.csv_output.QuoteEscapeCharacter

    if opts.out_ser.json_output is not None:
        json = s3_xml.SubElement(output_serialization, 'JSON')
        record_delimiter = s3_xml.SubElement(json, 'RecordDelimiter')
        record_delimiter.text = opts.out_ser.json_output.RecordDelimiter

    request_progress = s3_xml.SubElement(root, 'RequestProgress')
    enabled = s3_xml.SubElement(request_progress, 'Enabled')
    enabled.text = opts.req_progress.enabled.lower()

    data = io.BytesIO()
    s3_xml.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()


def xml_marshal_complete_multipart_upload(uploaded_parts):
    """
    Marshal's complete multipart upload request based on *uploaded_parts*.

    :param uploaded_parts: List of all uploaded parts, ordered by part number.
    :return: Marshalled XML data.
    """
    root = s3_xml.Element('CompleteMultipartUpload', {'xmlns': _S3_NAMESPACE})
    for uploaded_part in uploaded_parts:
        part_number = uploaded_part.part_number
        part = s3_xml.SubElement(root, 'Part')
        part_num = s3_xml.SubElement(part, 'PartNumber')
        part_num.text = str(part_number)
        etag = s3_xml.SubElement(part, 'ETag')
        etag.text = '"' + uploaded_part.etag + '"'
        data = io.BytesIO()
        s3_xml.ElementTree(root).write(data, encoding=None,
                                       xml_declaration=False)
    return data.getvalue()


def xml_marshal_bucket_notifications(notifications):
    """
    Marshals the notifications structure for sending to S3 compatible storage

    :param notifications: Dictionary with following structure:

    {
        'TopicConfigurations': [
            {
                'Id': 'string',
                'Arn': 'string',
                'Events': [
                    's3:ReducedRedundancyLostObject'|'s3:ObjectCreated:*'|'s3:ObjectCreated:Put'|'s3:ObjectCreated:Post'|'s3:ObjectCreated:Copy'|'s3:ObjectCreated:CompleteMultipartUpload'|'s3:ObjectRemoved:*'|'s3:ObjectRemoved:Delete'|'s3:ObjectRemoved:DeleteMarkerCreated',
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
                    's3:ReducedRedundancyLostObject'|'s3:ObjectCreated:*'|'s3:ObjectCreated:Put'|'s3:ObjectCreated:Post'|'s3:ObjectCreated:Copy'|'s3:ObjectCreated:CompleteMultipartUpload'|'s3:ObjectRemoved:*'|'s3:ObjectRemoved:Delete'|'s3:ObjectRemoved:DeleteMarkerCreated',
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
                    's3:ReducedRedundancyLostObject'|'s3:ObjectCreated:*'|'s3:ObjectCreated:Put'|'s3:ObjectCreated:Post'|'s3:ObjectCreated:Copy'|'s3:ObjectCreated:CompleteMultipartUpload'|'s3:ObjectRemoved:*'|'s3:ObjectRemoved:Delete'|'s3:ObjectRemoved:DeleteMarkerCreated',
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
    root = s3_xml.Element('NotificationConfiguration', {'xmlns': _S3_NAMESPACE})
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

    data = io.BytesIO()
    s3_xml.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()

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
        config_node = s3_xml.SubElement(node, element_name)

        if 'Id' in config:
            id_node = s3_xml.SubElement(config_node, 'Id')
            id_node.text = config['Id']

        arn_node = s3_xml.SubElement(
            config_node,
            NOTIFICATIONS_ARN_FIELDNAME_MAP[element_name]
        )
        arn_node.text = config['Arn']

        for event in config['Events']:
            event_node = s3_xml.SubElement(config_node, 'Event')
            event_node.text = event

        filter_rules = config.get('Filter', {}).get(
            'Key', {}).get('FilterRules', [])
        if filter_rules:
            filter_node = s3_xml.SubElement(config_node, 'Filter')
            s3key_node = s3_xml.SubElement(filter_node, 'S3Key')
            for filter_rule in filter_rules:
                filter_rule_node = s3_xml.SubElement(s3key_node, 'FilterRule')
                name_node = s3_xml.SubElement(filter_rule_node, 'Name')
                name_node.text = filter_rule['Name']
                value_node = s3_xml.SubElement(filter_rule_node, 'Value')
                value_node.text = filter_rule['Value']
    return node


def xml_marshal_delete_objects(object_names):
    """
    Marshal Multi-Object Delete request body from object names.

    :param object_names: List of object keys to be deleted.
    :return: Serialized XML string for multi-object delete request body.
    """
    root = s3_xml.Element('Delete')

    # use quiet mode in the request - this causes the S3 Server to
    # limit its response to only object keys that had errors during
    # the delete operation.
    quiet = s3_xml.SubElement(root, 'Quiet')
    quiet.text = "true"

    # add each object to the request.
    for object_name in object_names:
        object_elt = s3_xml.SubElement(root, 'Object')
        key_elt = s3_xml.SubElement(object_elt, 'Key')
        key_elt.text = object_name

    # return the marshalled xml.
    data = io.BytesIO()
    s3_xml.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()
