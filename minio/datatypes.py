# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2020 MinIO, Inc.
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

"""Response of ListBuckets API."""

from __future__ import absolute_import

from .helpers import strptime_rfc3339
from .xml import find, findall, findtext


class Bucket:
    """Bucket information."""

    def __init__(self, name, creation_date):
        self._name = name
        self._creation_date = creation_date

    @property
    def name(self):
        """Get name."""
        return self._name

    @property
    def creation_date(self):
        """Get creation date."""
        return self._creation_date


class ListAllMyBucketsResult:
    """LissBuckets API result."""

    def __init__(self, buckets):
        self._buckets = buckets

    @property
    def buckets(self):
        """Get buckets."""
        return self._buckets

    @classmethod
    def fromxml(cls, element):
        """Create new object with values from XML element."""
        element = find(element, "Buckets")
        buckets = []
        if element is not None:
            elements = findall(element, "Bucket")
            for bucket in elements:
                name = findtext(bucket, "Name", True)
                creation_date = findtext(bucket, "CreationDate")
                if creation_date:
                    creation_date = strptime_rfc3339(creation_date)
                buckets.append(Bucket(name, creation_date))
        return cls(buckets)
