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
PYTHON2 = (sys.version_info[0] == 2)

if PYTHON2:
    # pylint: disable=no-name-in-module
    # pylint: disable=no-name-in-module
    from urllib import quote as _quote
    from urllib import unquote, urlencode

    # pylint: disable=import-error
    from urlparse import parse_qs, urlsplit

    # Create missing types.
    bytes = str  # pylint: disable=redefined-builtin, invalid-name

    builtin_range = range  # pylint: disable=invalid-name
    builtin_str = str  # pylint: disable=invalid-name

    # Update better types.
    # pylint: disable=redefined-builtin, undefined-variable, invalid-name
    range = xrange
    # pylint: disable=redefined-builtin, undefined-variable, invalid-name
    str = unicode

    # Make importable.
    # pylint: disable=self-assigning-variable, undefined-variable, invalid-name
    basestring = basestring
else:
    from urllib.parse import parse_qs, unquote, urlencode, urlsplit  # pylint: disable=ungrouped-imports
    from urllib.parse import quote as _quote  # pylint: disable=ungrouped-imports

    # Create types to compat with python v2.
    builtin_range = range  # pylint: disable=invalid-name
    builtin_str = str  # pylint: disable=invalid-name

    # Create missing types.
    basestring = (str, bytes)  # pylint: disable=invalid-name
    long = int  # pylint: disable=invalid-name

    # Make importable.
    bytes = bytes  # pylint: disable=self-assigning-variable, invalid-name
    range = range  # pylint: disable=self-assigning-variable, invalid-name
    str = str  # pylint: disable=self-assigning-variable, invalid-name


# Make importable.
# to get rid of F401. pylint: disable=self-assigning-variable, invalid-name
unquote = unquote
# to get rid of F401. pylint: disable=self-assigning-variable, invalid-name
urlencode = urlencode
# to get rid of F401. pylint: disable=self-assigning-variable, invalid-name
urlsplit = urlsplit
# to get rid of F401. pylint: disable=self-assigning-variable, invalid-name
parse_qs = parse_qs


# Note earlier versions of minio.compat exposed urllib.quote as urlencode
def quote(resource):
    """
    This implementation of urllib.quote supports all unicode characters

    :param: resource: Resource value to be url encoded.
    """
    return _quote(
        resource.encode('utf-8') if isinstance(resource, str) else resource,
    )


def queryencode(query):
    """
    This implementation of queryencode supports all unicode characters

    :param: query: Query value to be url encoded.
    """
    return quote(query).replace('/', '%2F')
