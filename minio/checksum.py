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
import struct
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional

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
    hasher = hashlib.new(  # type: ignore[call-arg]
        "md5",
        usedforsecurity=False,
    )
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
    return "".join(f"{b:02x}" for b in data)


def hex_string_to_sum(value: str) -> bytes:
    """Decodes the specified Base16 (hex) encoded string to bytes."""
    if len(value) % 2 != 0:
        raise ValueError("Hex string length must be even")
    return bytes(int(value[i:i+2], 16) for i in range(0, len(value), 2))


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
        offset = offset or 0
        if length is None:
            length = len(data) - offset
        self._crc = binascii.crc32(
            data[offset:offset+length], self._crc,
        ) & 0xFFFFFFFF

    def sum(self) -> bytes:
        return struct.pack(">I", self._crc)

    def reset(self) -> None:
        self._crc = 0


def _generate_crc32c_table():
    """Generates CRC32C table."""
    table = [0] * 256
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if (crc & 1) else 0)
        table[i] = crc & 0xFFFFFFFF
    return table


_CRC32C_TABLE = _generate_crc32c_table()


class CRC32C(Hasher):
    """CRC32C Hasher."""

    def __init__(self):
        self._crc = 0xFFFFFFFF

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        offset = offset or 0
        if length is None:
            length = len(data) - offset
        for byte in data[offset:offset+length]:
            self._crc = _CRC32C_TABLE[
                (self._crc ^ byte) & 0xFF] ^ (self._crc >> 8)

    def sum(self) -> bytes:
        crc_final = (~self._crc) & 0xFFFFFFFF
        return crc_final.to_bytes(4, "big")

    def reset(self) -> None:
        self._crc = 0xFFFFFFFF


def _generate_crc64nvme_table():
    """Generates CRC64NVME table."""
    table = [0] * 256
    slicing8_table = [[0] * 256 for _ in range(8)]

    polynomial = 0x9A6C9329AC4BC9B5
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ polynomial
            else:
                crc >>= 1
        table[i] = crc & 0xFFFFFFFFFFFFFFFF

    slicing8_table[0] = table[:]
    for i in range(256):
        crc = table[i]
        for j in range(1, 8):
            crc = table[crc & 0xFF] ^ (crc >> 8)
            slicing8_table[j][i] = crc & 0xFFFFFFFFFFFFFFFF

    return table, slicing8_table


_CRC64NVME_TABLE, _SLICING8_TABLE_NVME = _generate_crc64nvme_table()


class CRC64NVME(Hasher):
    """CRC64 NVME checksum."""

    def __init__(self):
        self._crc = 0

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ):
        offset = offset or 0
        if length is None:
            length = len(data) - offset
        data = data[offset:offset + length]
        self._crc = ~self._crc & 0xFFFFFFFFFFFFFFFF
        offset = 0

        # Process in 8-byte chunks (little-endian)
        while len(data) >= 64 and (len(data) - offset) > 8:
            value = struct.unpack_from("<Q", data, offset)[0]
            self._crc ^= value
            self._crc = (
                _SLICING8_TABLE_NVME[7][self._crc & 0xFF] ^
                _SLICING8_TABLE_NVME[6][(self._crc >> 8) & 0xFF] ^
                _SLICING8_TABLE_NVME[5][(self._crc >> 16) & 0xFF] ^
                _SLICING8_TABLE_NVME[4][(self._crc >> 24) & 0xFF] ^
                _SLICING8_TABLE_NVME[3][(self._crc >> 32) & 0xFF] ^
                _SLICING8_TABLE_NVME[2][(self._crc >> 40) & 0xFF] ^
                _SLICING8_TABLE_NVME[1][(self._crc >> 48) & 0xFF] ^
                _SLICING8_TABLE_NVME[0][(self._crc >> 56)]
            ) & 0xFFFFFFFFFFFFFFFF
            offset += 8

        # Process remaining bytes
        for i in range(offset, length):
            self._crc = (
                _CRC64NVME_TABLE[(self._crc ^ data[i]) & 0xFF] ^
                (self._crc >> 8)
            ) & 0xFFFFFFFFFFFFFFFF

        self._crc = ~self._crc & 0xFFFFFFFFFFFFFFFF

    def reset(self):
        self._crc = 0

    def sum(self) -> bytes:
        value = self._crc
        return bytes([
            (value >> 56) & 0xFF,
            (value >> 48) & 0xFF,
            (value >> 40) & 0xFF,
            (value >> 32) & 0xFF,
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        ])


class HashlibHasher(Hasher, ABC):
    """Generic wrapper for hashlib algorithms."""

    def __init__(self, name: str):
        self._name = name
        self._hasher = hashlib.new(name)

    def update(
            self,
            data: bytes,
            offset: Optional[int] = None,
            length: Optional[int] = None,
    ) -> None:
        offset = offset or 0
        if length is None:
            length = len(data) - offset
        self._hasher.update(data[offset:offset+length])

    def sum(self) -> bytes:
        return self._hasher.digest()

    def reset(self) -> None:
        self._hasher = hashlib.new(self._name)


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
