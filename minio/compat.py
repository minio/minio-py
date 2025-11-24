# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
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

# pylint: disable=unused-import

"""Compatibility types."""

from __future__ import annotations

import errno
import os
import urllib.parse
from typing import Dict, Iterable, List, Mapping, Optional, Union

from urllib3._collections import HTTPHeaderDict

try:
    from urllib3.response import \
        BaseHTTPResponse as HTTPResponse  # type: ignore[attr-defined]
except ImportError:
    from urllib3.response import HTTPResponse

JSONDecodeError: type[ValueError]
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


class HTTPQueryDict(dict[str, List[str]]):
    """Dictionary for HTTP query parameters with multiple values per key."""

    def __init__(
        self,
        initial: Optional[
            Union[
                "HTTPQueryDict",
                Mapping[str, Union[str, Iterable[str]]],
            ]
        ] = None
    ):
        super().__init__()
        if initial:
            if not isinstance(initial, Mapping):
                raise TypeError(
                    "HTTPQueryDict expects a mapping-like object, "
                    f"got {type(initial).__name__}",
                )
            for key, value in initial.items():
                if isinstance(value, (str, bytes)):
                    self[key] = [value]
                else:
                    self[key] = list(value)

    def __setitem__(self, key: str, value: Union[str, Iterable[str]]) -> None:
        super().__setitem__(
            key,
            [value] if isinstance(value, (str, bytes)) else list(value),
        )

    def copy(self) -> "HTTPQueryDict":
        return HTTPQueryDict(self)

    def extend(
        self,
        other: Optional[
            Union[
                "HTTPQueryDict",
                Mapping[str, Union[str, Iterable[str]]],
            ]
        ],
    ) -> "HTTPQueryDict":
        """Merges other keys and values."""
        if other is None:
            return self
        if not isinstance(other, Mapping):
            raise TypeError(
                "extend() expects a mapping-like object, "
                f"got {type(other).__name__}",
            )
        for key, value in other.items():
            normalized = (
                [value] if isinstance(value, (str, bytes)) else list(value)
            )
            if key in self:
                self[key] += normalized
            else:
                self[key] = normalized
        return self

    def __str__(self) -> str:
        """Convert dictionary to a URL-encoded query string."""
        query_list = [(k, v) for k, values in self.items() for v in values]
        query_list.sort(key=lambda x: (x[0], x[1]))  # Sort by key, then value
        return urllib.parse.urlencode(query_list, quote_via=urllib.parse.quote)


def quote(resource: str, safe: str = "/") -> str:
    """
    Wrapper to urllib.parse.quote() replacing back to '~' for older python
    versions.
    """
    return urllib.parse.quote(
        resource, safe=safe, encoding=None, errors=None,
    ).replace("%7E", "~")


def queryencode(query: str) -> str:
    """Encode query parameter value."""
    return quote(query, safe="")


def makedirs(path: str):
    """Wrapper of os.makedirs() ignores errno.EEXIST."""
    try:
        if path:
            os.makedirs(path)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise

        if not os.path.isdir(path):
            raise ValueError(f"path {path} is not a directory") from exc
