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
minio.xml_marshal
~~~~~~~~~~~~~~~

This module contains the simple wrappers for XML marshaller's.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from __future__ import absolute_import
import io

from xml.etree import ElementTree as s3_xml

_S3_NAMESPACE = 'http://s3.amazonaws.com/doc/2006-03-01/'


def xml_marshal_bucket_constraint(region):
    """
    Marshal's bucket constraint based on *region*
.
    :param region: Region name of a given bucket.
    :return: Marshalled XML data.
    """
    root = s3_xml.Element('CreateBucketConfiguration', {'xmlns': _S3_NAMESPACE})
    location_constraint = s3_xml.SubElement(root, 'LocationConstraint')
    location_constraint.text = region
    data = io.BytesIO()
    s3_xml.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()


def xml_marshal_complete_multipart_upload(uploaded_parts):
    """
    Marshal's complete multipart upload request based on *uploaded_parts*.
.
    :param uploaded_parts: List of all uploaded parts ordered in the
           way they were uploaded.
    :return: Marshalled XML data.
    """
    root = s3_xml.Element('CompleteMultipartUpload', {'xmlns': _S3_NAMESPACE})
    for part_number in uploaded_parts.keys():
        part = s3_xml.SubElement(root, 'Part')
        part_num = s3_xml.SubElement(part, 'PartNumber')
        part_num.text = str(part_number)
        etag = s3_xml.SubElement(part, 'ETag')
        etag.text = '"' + uploaded_parts[part_number].etag + '"'
        data = io.BytesIO()
        s3_xml.ElementTree(root).write(data, encoding=None,
                                       xml_declaration=False)
    return data.getvalue()
