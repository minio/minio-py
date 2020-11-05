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

from .definitions import ListMultipartUploadsResult, ListPartsResult
from .error import S3Error
from .helpers import strptime_rfc3339

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


def parse_new_multipart_upload(data):
    """
    Parser for new multipart upload response.

    :param data: Response data for new multipart upload.
    :return: Returns a upload id.
    """
    root = S3Element.fromstring('InitiateMultipartUploadResult', data)
    return root.get_child_text('UploadId')


def parse_list_multipart_uploads(data):
    """Parse ListMultipartUploads API resppnse XML."""
    return ListMultipartUploadsResult(
        S3Element.fromstring("ListMultipartUploadsResult", data),
    )


def parse_list_parts(data):
    """Parse ListParts API resppnse XML."""
    return ListPartsResult(S3Element.fromstring("ListPartsResult", data))
