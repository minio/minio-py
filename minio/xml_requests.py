# Minimal Object Storage Library, (C) 2015 Minio, Inc.
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
from xml.etree import ElementTree

__author__ = 'minio'


def bucket_constraint(region):
    root = ElementTree.Element('CreateBucketConfiguration', {'xmlns': 'http://s3.amazonaws.com/doc/2006-03-01/'})
    location_constraint = ElementTree.SubElement(root, 'LocationConstraint')
    location_constraint.text = region
    data = []
    mock_file = MockFile()
    mock_file.write = data.append
    ElementTree.ElementTree(root).write(mock_file, encoding=None, xml_declaration=False)
    return b''.join(data)


class MockFile(object):
    pass
