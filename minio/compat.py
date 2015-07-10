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


def compat_urldecode_key(text):
    if sys.version_info < (3, 0):
        return compat_url2pathname(text.encode('utf-8'))
    else:
        return compat_url2pathname(text)


compat_str_type = None
if sys.version_info < (3, 0):
    compat_str_type = basestring
else:
    compat_str_type = str
