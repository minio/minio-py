# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2016 Minio, Inc.
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
minio.copy_conditions
~~~~~~~~~~~~~~~

This module contains :class:`CopyConditions <CopyConditions>` implementation.

:copyright: (c) 2016 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from .helpers import (is_non_empty_string, is_valid_bucket_name)

# CopyCondition explanation:
# http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectCOPY.html
#
# Example:
#
#  copyCondition {
#      key: "x-amz-copy-if-modified-since",
#      value: "Tue, 15 Nov 1994 12:45:26 GMT",
#
class CopyConditions(object):
    """
    A :class:`CopyConditions <CopyConditions>` collection of
       supported CopyObject conditions.

        - x-amz-copy-source-if-match
        - x-amz-copy-source-if-none-match
        - x-amz-copy-source-if-unmodified-since
        - x-amz-copy-source-if-modified-since

    """
    def __init__(self):
        self._copy_conditions = {}

    def set_match_etag(self, etag):
        """
        """
        is_non_empty_string(etag)
        self._copy_conditions['X-Amz-Copy-Source-If-Match'] = etag

    def set_match_etag_except(self, etag):
        """
        """
        is_non_empty_string(etag)
        self._copy_conditions['X-Amz-Copy-Source-If-None-Match'] = etag

    def set_unmodified_since(self, mod_time):
        """
        """
        time = mod_time.strftime('%a, %d %b %Y %H:%M:%S GMT')
        self._copy_conditions['X-Amz-Copy-Source-If-Unmodified-Since'] = time

    def set_modified_since(self, mod_time):
        """
        """
        time = mod_time.strftime('%a, %d %b %Y %H:%M:%S GMT')
        self._copy_conditions['X-Amz-Copy-Source-If-Modified-Since'] = time

    def get(self):
        """
        Returns all the set copy conditions.
        """
        return self._copy_conditions
