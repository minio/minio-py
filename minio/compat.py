# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016 Minio, Inc.
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

:copyright: (c) 2015, 2016 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import sys

#: Python 2.x?
_is_py2 = (sys.version_info[0] == 2)

#: Python 3.x?
_is_py3 = (sys.version_info[0] == 3)

if _is_py2:
    from urllib import quote
    _urlencode = quote

    from urllib import unquote
    urldecode = unquote

    import urlparse
    urlsplit = urlparse.urlsplit
    parse_qs = urlparse.parse_qs

    ## Create missing types.
    bytes = str

    ## Update better types.
    builtin_range = range
    range = xrange
    builtin_str = str
    str = unicode

    ## Add missing imports
    basestring = basestring
elif _is_py3:
    from urllib.request import quote
    _urlencode = quote

    from urllib.request import unquote
    urldecode = unquote

    import urllib.parse
    urlsplit = urllib.parse.urlsplit
    parse_qs = urllib.parse.parse_qs

    ## Create types to compat with py2.
    builtin_range = range
    builtin_str = str

    ## Create missing types.
    basestring = (str, bytes)
    long = int

    ## Add missing imports
    bytes = bytes
    range = range
    str = str

numeric_types = (int, long, float)

def urlencode(resource):
    """
    This implementation of urlencode supports all unicode characters

    :param: resource: Resource value to be url encoded.
    """
    if isinstance(resource, str):
        return _urlencode(resource.encode('utf-8'))

    return _urlencode(resource)

def queryencode(query):
    """
    This implementation of queryencode supports all unicode characters

    :param: query: Query value to be url encoded.
    """
    return urlencode(query).replace('/', '%2F')
