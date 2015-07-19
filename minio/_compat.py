# -*- coding: utf-8 -*-
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

import sys

try:
    from urllib.parse import urlparse as compat_urllib_parse
except ImportError:  # python 2
    from urlparse import urlparse as compat_urllib_parse

try:
    from urllib.request import pathname2url as compat_pathname2url
except ImportError:  # python 2
    from urllib import pathname2url as compat_pathname2url

try:
    from urllib.request import url2pathname as compat_url2pathname
except ImportError:  # python 2
    from urllib import url2pathname as compat_url2pathname


def urlencode(text):
    if sys.version_info < (3, 0):
        return compat_url2pathname(text.encode('utf-8'))
    else:
        return compat_url2pathname(text)


compat_str_type = None
if sys.version_info < (3, 0):
    compat_str_type = basestring
else:
    compat_str_type = str
