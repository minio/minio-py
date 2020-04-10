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


class FoldCaseDict(dict):
    def __init__(self, dictionary={}):
        self._data = self.__create(dictionary)

    def __create(self, value):
        if not isinstance(value, dict):
            return value

        data = {}
        for k, v in value.items():
            data[k.lower()] = FoldCaseDict(v) if isinstance(v, dict) else v
        return data

    def __getitem__(self, key):
        return self._data.__getitem__(key.lower())

    def __contains__(self, key):
        return self._data.__contains__(key.lower())

    def __setitem__(self, key, value):
        self._data.__setitem__(key.lower(), self.__create(value))

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
        return self._data.has_key(key.lower())

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def iteritems(self):
        return self._data.iteritems()

    def iterkeys(self):
        for k in self._data.keys():
            yield k

    def itervalues(self):
        for v in self._data.values():
            yield v

    def update(self, dictionary):
        if isinstance(dictionary, dict):
            dictionary = FoldCaseDict(dictionary)
        elif isinstance(dictionary, FoldCaseDict):
            pass
        else:
            raise TypeError

        self._data.update(dictionary._data)

    def copy(self):
        return FoldCaseDict(self._data.copy())

    def clear(self):
        self._data = {}

    def pop(self, key):
        return self._data.pop(key.lower())

    def popitem(self):
        return self._data.popitem()
