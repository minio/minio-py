# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 MinIO, Inc.
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
minio.compat
~~~~~~~~~~~~

This module implements python 2.x and 3.x compatibility layer.

:copyright: (c) 2015, 2016 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import sys

#: Python 2.x?
_is_py2 = (sys.version_info[0] == 2)

#: Python 3.x?
_is_py3 = (sys.version_info[0] == 3)

if _is_py2:
    from Queue import Queue
    queue = Queue

    from Queue import Empty
    queue_empty = Empty

    from urllib import quote, unquote, urlencode

    from urlparse import urlsplit, parse_qs

    # Create missing types.
    bytes = str

    # Update better types.
    builtin_range = range
    range = xrange
    builtin_str = str
    str = unicode

    # Add missing imports
    basestring = basestring
elif _is_py3:
    from queue import Queue
    queue = Queue

    from queue import Empty
    queue_empty = Empty

    from urllib.parse import quote, unquote, urlsplit, parse_qs, urlencode
    unquote = unquote  # to get rid of F401
    urlencode = urlencode  # to get rid of F401
    urlsplit = urlsplit  # to get rid of F401
    parse_qs = parse_qs  # to get rid of F401

    # Create types to compat with py2.
    builtin_range = range
    builtin_str = str

    # Create missing types.
    basestring = (str, bytes)
    long = int

    # Add missing imports
    bytes = bytes
    range = range
    str = str


# Note earlier versions of minio.compat exposed urllib.quote as urlencode
def _quote(resource):
    """
    This implementation of urllib.quote supports all unicode characters

    :param: resource: Resource value to be url encoded.
    """
    if isinstance(resource, str):
        return quote(resource.encode('utf-8'))

    return quote(resource)


def queryencode(query):
    """
    This implementation of queryencode supports all unicode characters

    :param: query: Query value to be url encoded.
    """
    return _quote(query).replace('/', '%2F')
