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
from io import BytesIO
from xml.etree import ElementTree

__author__ = 'minio'


def bucket_constraint(region):
    root = ElementTree.Element('CreateBucketConfiguration', {'xmlns': 'http://s3.amazonaws.com/doc/2006-03-01/'})
    location_constraint = ElementTree.SubElement(root, 'LocationConstraint')
    location_constraint.text = region
    data = BytesIO()
    ElementTree.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()


def get_complete_multipart_upload(etags):
    root = ElementTree.Element('CompleteMultipartUpload', {'xmlns': 'http://s3.amazonaws.com/doc/2006-03-01/'})

    for i in range(0, len(etags)):
        part = ElementTree.SubElement(root, 'Part')
        part_number = ElementTree.SubElement(part, 'PartNumber')
        part_number.text = str(i + 1)
        etag = ElementTree.SubElement(part, 'ETag')
        etag.text = etags[i]
        data = BytesIO()
        ElementTree.ElementTree(root).write(data, encoding=None, xml_declaration=False)
    return data.getvalue()
