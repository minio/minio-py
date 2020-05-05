# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2017 MinIO, Inc.
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
minio.fold_case_dict

This module implements a case insensitive dictionary.

:copyright: (c) 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from .compat import PYTHON2


def _to_dict(value):
    """Create value to dictionary."""
    if not isinstance(value, dict):
        return value

    data = {}
    for key, val in value.items():
        data[key.lower()] = FoldCaseDict(val) if isinstance(val, dict) else val
    return data


class FoldCaseDict(dict):
    """Dictionary deals with case insensitive key."""

    def __init__(self, dictionary=None):
        super(FoldCaseDict, self).__init__()
        self._data = _to_dict(dictionary) if dictionary else {}

    def __getitem__(self, key):
        return self._data.__getitem__(key.lower())

    def __contains__(self, key):
        return self._data.__contains__(key.lower())

    def __setitem__(self, key, value):
        self._data.__setitem__(key.lower(), _to_dict(value))

    def __delitem__(self, key):
        self._data.__delitem__(key.lower())

    def __iter__(self):
        return self._data.__iter__()

    def __len__(self):
        return self._data.__len__()

    def __eq__(self, other):
        if isinstance(other, dict):
            other = FoldCaseDict(other)
        elif isinstance(other, FoldCaseDict):
            pass
        else:
            raise NotImplementedError

        return self._data.__eq__(other._data)

    def __repr__(self):
        return self._data.__repr__()

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)

    def has_key(self, key):
        """Test for the presence of key in the dictionary."""
        return key.lower() in self._data

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def iteritems(self):
        """Return an iterator over the dictionary’s (key, value) pairs."""
        if PYTHON2:
            return self._data.iteritems()  # pylint: disable=no-member
        return self._data.items()

    def iterkeys(self):
        """Return an iterator over the dictionary’s keys."""
        for k in self._data.keys():
            yield k

    def itervalues(self):
        """Return an iterator over the dictionary’s values."""
        for value in self._data.values():
            yield value

    def update(self, dictionary):
        if isinstance(dictionary, dict):
            dictionary = FoldCaseDict(dictionary)
        elif isinstance(dictionary, FoldCaseDict):
            pass
        else:
            raise TypeError

        self._data.update(dictionary._data)  # pylint: disable=protected-access

    def copy(self):
        return FoldCaseDict(self._data.copy())

    def clear(self):
        self._data = {}

    def pop(self, key):
        return self._data.pop(key.lower())

    def popitem(self):
        return self._data.popitem()
