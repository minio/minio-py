# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2017 Minio, Inc.
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

:copyright: (c) 2017 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

class FoldCaseDict(dict):
    def __init__(self, dictionary={}):
        self._data = self.__create(dictionary)

    def __create(self, value):
        if isinstance(value, dict):
            data = {}
            for k, v in value.items():
                if isinstance(v, dict):
                    data[k.lower()] = FoldCaseDict(self.__create(v))
                else:
                    data[k.lower()] = v
            return data
        else:
            return value

    def __getitem__(self, item):
        return self._data[item.lower()]

    def __contains__(self, item):
        return item.lower() in self._data

    def __setitem__(self, key, value):
        self._data[key.lower()] = self.__create(value)

    def __delitem__(self, key):
        del self._data[key.lower()]

    def __iter__(self):
        return (k for k in self._data.keys())

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        if isinstance(other, dict):
            other = FoldCaseDict(other)
        elif isinstance(other, FoldCaseDict):
            pass
        else:
            raise NotImplementedError

        # Compare insensitively
        return self.items() == other.items()

    def __repr__(self):
        return str(self._data)

    def get(self, key, default=None):
        if not key.lower() in self:
            return default
        else:
            return self[key]

    def has_key(self, key):
        return key.lower() in self

    def items(self):
        return [(k, v) for k, v in self.iteritems()]

    def keys(self):
        return [k for k in self.iterkeys()]

    def values(self):
        return [v for v in self.itervalues()]

    def iteritems(self):
        for k, v in self._data.items():
            yield k, v

    def iterkeys(self):
        for k, v in self._data.items():
            yield k

    def itervalues(self):
        for k, v in self._data.items():
            yield v

    def update(self, dictionary):
        if not (isinstance(dictionary, dict) or
                isinstance(dictionary, FoldCaseDict)):
            raise TypeError

        for k, v in dictionary.items():
            self[k] = v

    def copy(self):
        copy_dict = FoldCaseDict()
        for k, v in self._data.items():
            copy_dict[k] = v
        return copy_dict

    def clear(self):
        self._data = {}

    def pop(self, key):
        return self._data.pop(key)

    def popitem(self):
        return self._data.popitem()
