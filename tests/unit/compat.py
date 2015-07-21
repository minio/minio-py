import sys

try:
    from urllib.parse import urlparse as compat_urllib_parse
except ImportError:  # python 2
    from urlparse import urlparse as compat_urllib_parse

strtype = None
if sys.version_info < (3, 0):
    strtype = basestring
else:
    strtype = str
