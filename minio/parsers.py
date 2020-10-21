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

from xml.etree import ElementTree

from .error import S3Error


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
