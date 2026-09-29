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

"""Checksum functions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import struct
from abc import ABC, abstractmethod
from enum import Enum
from types import ModuleType
from typing import Dict, List, Optional

# Optional native CRC implementations; pure-Python fallback is used otherwise.
# awscrt provides CRC32C and CRC64NVME; google_crc32c provides CRC32C only and
# is used when awscrt is unavailable.
_awscrt_checksums: Optional[ModuleType]
try:
    _awscrt_checksums = importlib.import_module("awscrt.checksums")
except ImportError:
    _awscrt_checksums = None

# Import the C extension directly; the google_crc32c package silently falls
# back to its own pure-Python implementation, which is slower than ours.
_google_crc32c: Optional[ModuleType]
try:
    _google_crc32c = importlib.import_module("google_crc32c.cext")
except ImportError:
    _google_crc32c = None

# MD5 hash of zero length byte array.
ZERO_MD5_HASH = "1B2M2Y8AsgTpgAmY7PhCfg=="
# SHA-256 hash of zero length byte array.
ZERO_SHA256_HASH = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"


def md5sum_hash(data: Optional[str | bytes]) -> Optional[str]:
    """Compute MD5 of data and return hash as Base64 encoded value."""
    if data is None:
        return None

    # indicate md5 hashing algorithm is not used in a security context.
    # Refer https://bugs.python.org/issue9216 for more information.
    hasher = hashlib.new("md5", usedforsecurity=False)
    hasher.update(data.encode() if isinstance(data, str) else data)
    md5sum = base64.b64encode(hasher.digest())
    return md5sum.decode() if isinstance(md5sum, bytes) else md5sum


def sha256_hash(data: Optional[str | bytes]) -> str:
    """Compute SHA-256 of data and return hash as hex encoded value."""
    data = data or b""
    hasher = hashlib.sha256()
    hasher.update(data.encode() if isinstance(data, str) else data)
    sha256sum = hasher.hexdigest()
    if isinstance(sha256sum, bytes):
        return sha256sum.decode()
    return sha256sum


def base64_string(data: bytes) -> str:
    """Encodes the specified bytes to Base64 string."""
    return base64.b64encode(data).decode("ascii")


def base64_string_to_sum(value: str) -> bytes:
    """Decodes the specified Base64 encoded string to bytes."""
    return base64.b64decode(value)


def hex_string(data: bytes) -> str:
    """Encodes the specified bytes to Base16 (hex) string."""
    return data.hex()


def hex_string_to_sum(value: str) -> bytes:
    """Decodes the specified Base16 (hex) encoded string to bytes."""
    if len(value) % 2 != 0:
        raise ValueError("Hex string length must be even")
    return bytes(int(value[i:i+2], 16) for i in range(0, len(value), 2))


def _view(
        data: bytes,
        offset: Optional[int] = None,
        length: Optional[int] = None,
) -> memoryview:
    """Returns data[offset:offset+length] as memoryview without copying."""
    offset = offset or 0
    view = memoryview(data)
    return view[offset:] if length is None else view[offset:offset+length]


class Hasher(ABC):
    """Checksum hasher interface."""

    @abstractmethod
    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        """Update the hash with bytes from b[off:off+length]."""

    @abstractmethod
    def sum(self) -> bytes:
        """Return the final digest."""

    @abstractmethod
    def reset(self) -> None:
        """Reset the hasher state."""


class CRC32(Hasher):
    """CRC32 Hasher using binascii.crc32."""

    def __init__(self):
        self._crc = 0

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        self._crc = binascii.crc32(
            _view(data, offset, length), self._crc,
        ) & 0xFFFFFFFF

    def sum(self) -> bytes:
        return struct.pack(">I", self._crc)

    def reset(self) -> None:
        self._crc = 0


def _generate_crc_tables(polynomial: int) -> tuple[list[int], ...]:
    """Generates slicing-by-16 lookup tables for reflected CRC polynomial."""
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (polynomial if crc & 1 else 0)
        table.append(crc)
    tables = [table]
    for _ in range(15):
        tables.append([table[crc & 0xFF] ^ (crc >> 8) for crc in tables[-1]])
    return tuple(tables)


_CRC32C_TABLES = _generate_crc_tables(0x82F63B78)
_CRC64NVME_TABLES = _generate_crc_tables(0x9A6C9329AC4BC9B5)


def _crc32c_update(crc: int, data: memoryview) -> int:
    """Extends CRC32C checksum crc with data.

    Uses slicing-by-16: each loop iteration consumes 16 bytes with one table
    lookup per byte, which minimizes Python bytecode executed per byte.
    """
    # pylint: disable=invalid-name,too-many-locals
    # pylint: disable=unbalanced-tuple-unpacking
    (t0, t1, t2, t3, t4, t5, t6, t7,
     t8, t9, t10, t11, t12, t13, t14, t15) = _CRC32C_TABLES
    crc ^= 0xFFFFFFFF
    end = len(data) - len(data) % 16
    for (b0, b1, b2, b3, b4, b5, b6, b7,
         b8, b9, b10, b11, b12, b13, b14, b15) in struct.iter_unpack(
             "16B", data[:end]):
        crc = (
            t15[b0 ^ (crc & 0xFF)] ^
            t14[b1 ^ ((crc >> 8) & 0xFF)] ^
            t13[b2 ^ ((crc >> 16) & 0xFF)] ^
            t12[b3 ^ (crc >> 24)] ^
            t11[b4] ^ t10[b5] ^ t9[b6] ^ t8[b7] ^
            t7[b8] ^ t6[b9] ^ t5[b10] ^ t4[b11] ^
            t3[b12] ^ t2[b13] ^ t1[b14] ^ t0[b15]
        )
    for byte in data[end:]:
        crc = t0[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _crc64nvme_update(crc: int, data: memoryview) -> int:
    """Extends CRC64NVME checksum crc with data using slicing-by-16."""
    # pylint: disable=invalid-name,too-many-locals
    # pylint: disable=unbalanced-tuple-unpacking
    (t0, t1, t2, t3, t4, t5, t6, t7,
     t8, t9, t10, t11, t12, t13, t14, t15) = _CRC64NVME_TABLES
    crc ^= 0xFFFFFFFFFFFFFFFF
    end = len(data) - len(data) % 16
    for (b0, b1, b2, b3, b4, b5, b6, b7,
         b8, b9, b10, b11, b12, b13, b14, b15) in struct.iter_unpack(
             "16B", data[:end]):
        crc = (
            t15[b0 ^ (crc & 0xFF)] ^
            t14[b1 ^ ((crc >> 8) & 0xFF)] ^
            t13[b2 ^ ((crc >> 16) & 0xFF)] ^
            t12[b3 ^ ((crc >> 24) & 0xFF)] ^
            t11[b4 ^ ((crc >> 32) & 0xFF)] ^
            t10[b5 ^ ((crc >> 40) & 0xFF)] ^
            t9[b6 ^ ((crc >> 48) & 0xFF)] ^
            t8[b7 ^ (crc >> 56)] ^
            t7[b8] ^ t6[b9] ^ t5[b10] ^ t4[b11] ^
            t3[b12] ^ t2[b13] ^ t1[b14] ^ t0[b15]
        )
    for byte in data[end:]:
        crc = t0[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


class CRC32C(Hasher):
    """CRC32C Hasher."""

    def __init__(self):
        self._crc = 0

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        view = _view(data, offset, length)
        if _awscrt_checksums:
            self._crc = _awscrt_checksums.crc32c(view, self._crc)
        elif _google_crc32c:
            # google_crc32c accepts bytes only; avoid copying whole bytes.
            whole = isinstance(data, bytes) and len(view) == len(data)
            self._crc = _google_crc32c.extend(
                self._crc, data if whole else bytes(view),
            )
        else:
            self._crc = _crc32c_update(self._crc, view)

    def sum(self) -> bytes:
        return self._crc.to_bytes(4, "big")

    def reset(self) -> None:
        self._crc = 0


class CRC64NVME(Hasher):
    """CRC64 NVME checksum."""

    def __init__(self):
        self._crc = 0

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        view = _view(data, offset, length)
        if _awscrt_checksums:
            self._crc = _awscrt_checksums.crc64nvme(view, self._crc)
        else:
            self._crc = _crc64nvme_update(self._crc, view)

    def sum(self) -> bytes:
        return self._crc.to_bytes(8, "big")

    def reset(self) -> None:
        self._crc = 0


class HashlibHasher(Hasher, ABC):
    """Generic wrapper for hashlib algorithms."""

    def __init__(self, name: str):
        self._name = name
        self._hasher = self._new()

    def _new(self):
        """Creates new hashlib object."""
        # MD5 is used as a checksum, not for security; this allows MD5 on
        # FIPS enabled systems. Refer https://bugs.python.org/issue9216
        if self._name == "md5":
            return hashlib.new("md5", usedforsecurity=False)
        return hashlib.new(self._name)

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        self._hasher.update(_view(data, offset, length))

    def sum(self) -> bytes:
        return self._hasher.digest()

    def reset(self) -> None:
        self._hasher = self._new()


class SHA1(HashlibHasher):
    """SHA1 checksum."""

    def __init__(self):
        super().__init__("sha1")


class SHA256(HashlibHasher):
    """SHA256 checksum."""

    def __init__(self):
        super().__init__("sha256")

    @classmethod
    def hash(
        cls,
        data: str | bytes,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> bytes:
        """Gets sum of given data."""
        hasher = cls()
        hasher.update(
            data if isinstance(data, bytes) else data.encode(),
            offset,
            length,
        )
        return hasher.sum()


class MD5(HashlibHasher):
    """MD5 checksum."""

    def __init__(self):
        super().__init__("md5")

    @classmethod
    def hash(
        cls,
        data: bytes,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> bytes:
        """Gets sum of given data."""
        hasher = cls()
        hasher.update(data, offset, length)
        return hasher.sum()


class Type(Enum):
    """Checksum algorithm type."""
    COMPOSITE = "COMPOSITE"
    FULL_OBJECT = "FULL_OBJECT"


class Algorithm(Enum):
    """Checksum algorithm."""
    CRC32 = "crc32"
    CRC32C = "crc32c"
    CRC64NVME = "crc64nvme"
    SHA1 = "sha1"
    SHA256 = "sha256"
    MD5 = "md5"

    def __str__(self) -> str:
        return self.value

    def header(self) -> str:
        """Gets headers for this algorithm."""
        return (
            "Content-MD5" if self == MD5 else f"x-amz-checksum-{self.value}"
        )

    def full_object_support(self) -> bool:
        """Checks whether this algorithm supports full object."""
        return self in {CRC32, CRC32C, CRC64NVME}

    def composite_support(self) -> bool:
        """Checks whether this algorithm supports composite."""
        return self in {CRC32, CRC32C, SHA1, SHA256}

    def validate(self, algo_type: Type):
        """Validates given algorithm type for this algorithm."""
        if not (
            (self.composite_support() and algo_type == Type.COMPOSITE)
            or (self.full_object_support() and algo_type == Type.FULL_OBJECT)
        ):
            raise ValueError(
                f"algorithm {self.name} does not support {algo_type.name} type",
            )

    def hasher(self):
        """Gets hasher for this algorithm."""
        if self == Algorithm.CRC32:
            return CRC32()
        if self == Algorithm.CRC32C:
            return CRC32C()
        if self == Algorithm.CRC64NVME:
            return CRC64NVME()
        if self == Algorithm.SHA1:
            return SHA1()
        if self == Algorithm.SHA256:
            return SHA256()
        if self == Algorithm.MD5:
            return MD5()
        return None


def new_hashers(
        algorithms: Optional[List[Algorithm]],
) -> Optional[Dict[Algorithm, "Hasher"]]:
    """Creates new hasher map for given algorithms."""
    hashers = {}
    if algorithms:
        for algo in algorithms:
            if algo and algo not in hashers:
                hashers[algo] = algo.hasher()
    return hashers if hashers else None


def update_hashers(
        hashers: Optional[Dict[Algorithm, "Hasher"]],
        data: bytes,
        length: int,
):
    """Updates hashers with given data and length."""
    if not hashers:
        return
    for hasher in hashers.values():
        hasher.update(data, 0, length)


def reset_hashers(hashers: Optional[Dict[Algorithm, "Hasher"]]):
    """Resets hashers."""
    if not hashers:
        return
    for hasher in hashers.values():
        hasher.reset()


def make_headers(
    hashers: Optional[Dict[Algorithm, "Hasher"]],
    add_content_sha256: bool,
    add_sha256_checksum: bool,
    algorithm_only: bool = False
) -> Dict[str, str]:
    """Makes headers for hashers.

    Args:
        hashers: Dictionary of algorithm to hasher instances
        add_content_sha256: Whether to add x-amz-content-sha256 header
        add_sha256_checksum: Whether to add SHA256 checksum header
        algorithm_only: If True, only include algorithm declaration header,
                       not checksum value headers
    """
    headers = {}
    if hashers:
        for algo, hasher in hashers.items():
            sum_bytes = hasher.sum()
            if algo == Algorithm.SHA256:
                if add_content_sha256:
                    headers["x-amz-content-sha256"] = hex_string(sum_bytes)
                if not add_sha256_checksum:
                    continue
            headers["x-amz-sdk-checksum-algorithm"] = str(algo)
            if not algorithm_only:
                headers[algo.header()] = base64_string(sum_bytes)
    return headers
