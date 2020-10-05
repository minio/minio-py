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
