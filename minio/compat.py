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

import sys

try:
    from urllib.parse import urlsplit
except ImportError:  # python 2
    from urlparse import urlsplit

try:
    from urllib.request import pathname2url as urlencode
except ImportError:  # python 2
    from urllib import pathname2url as urlencode

try:
    from urllib.request import url2pathname as urldecode
except ImportError:  # python 2
    from urllib import url2pathname as urldecode


strtype = None
if sys.version_info < (3, 0):
    strtype = basestring
else:
    strtype = str
