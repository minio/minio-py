import sys

try:
    from urllib.parse import urlparse as compat_urllib_parse
except ImportError:  # python 2
    from urlparse import urlparse as compat_urllib_parse

try:
    from urllib.request import pathname2url as compat_pathname2url
except ImportError:  # python 2
    from urllib import pathname2url as compat_pathname2url


compat_str_type = None
if sys.version_info < (3, 0):
    compat_str_type = basestring
else:
    compat_str_type = str
