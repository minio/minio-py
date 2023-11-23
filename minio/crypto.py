# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2015, 2016, 2017 MinIO, Inc.
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

# pylint: disable=too-many-lines,disable=too-many-branches,too-many-statements
# pylint: disable=too-many-arguments

"""Cryptography to read and write encrypted MinIO Admin payload"""

import os
import typing

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES, ChaCha20_Poly1305

# Encrypted message format:
#  header | encrypted data
#   41       ~ len(data)
#
# Encrypted data:
# payload (16 KB) | tag (16 bytes)
# payload (16 KB) | tag (16 bytes)
# payload (16 KB) | tag (16 bytes)
# ...
# payload (1 byte - 16 KB) | tag (16 bytes)
#
# Header format:
# salt | AEAD ID | nonce
#  32      1         8
#
# Notes: additional data for the cipher algo (wihin every single encrypted
#   data payload) needs to contain 0x00 byte EXCEPT the last one. The last
#   is noted by 0x80 byte
#
# Important links:
#  * https://github.com/minio/madmin-go/blob/main/encrypt.go#L43-L49
#  * https://github.com/secure-io/sio-go/blob/master/sio.go#L25
#  * https://github.com/secure-io/sio/blob/master/img/channel_construction.svg
#  * https://github.com/secure-io/sio-go/tree/master

_STD_PACKAGE_SIZE = 1 << 14  # 16KB
_SALT_LEN = 32
_NONCE_LEN = 8
_TAG_LEN = 16
_SALT_END = _SALT_LEN
_AEAD_ID_END = _SALT_LEN + 1
_NONCE_END = _AEAD_ID_END + _NONCE_LEN


class CryptoException(Exception):
    """Exception for crypto operations"""


class AesGcmCipherProvider:
    """AES-GCM cipher provider"""

    @staticmethod
    def get_cipher(key: bytes, nonce: bytes):
        """Get cipher"""
        return AES.new(key, AES.MODE_GCM, nonce)


class ChaCha20Poly1305CipherProvider:
    """ChaCha20Poly1305 cipher provider"""

    @staticmethod
    def get_cipher(key: bytes, nonce: bytes):
        """Get cipher"""
        return ChaCha20_Poly1305.new(key=key, nonce=nonce)


# FUTURE: Add support for messages >16KB
def encrypt(payload: bytes, password: str) -> bytes:
    """
    Encrypts data using AES-GCM using a 256-bit Argon2ID key.
    To see the original implementation in Go, check out the madmin-go library
    (https://github.com/minio/madmin-go/blob/main/encrypt.go#L38)
    """
    cipher_provider = AesGcmCipherProvider()
    nonce = os.urandom(_NONCE_LEN)
    salt = os.urandom(_SALT_LEN)

    padded_nonce = [0] * (_NONCE_LEN + 4)
    padded_nonce[:_NONCE_LEN] = nonce

    key = _generate_key(password.encode(), salt)
    additional_data = _generate_additional_data(
        cipher_provider, key, bytes(padded_nonce)
    )
    _mark_as_last(additional_data)
    additional_data = bytes(additional_data)

    _update_nonce_id(padded_nonce, 1)

    cipher = cipher_provider.get_cipher(key, bytes(padded_nonce))
    cipher.update(additional_data)
    encrypted_data, mac = cipher.encrypt_and_digest(payload)

    payload = salt
    payload += bytes([0x00])
    payload += nonce
    payload += encrypted_data
    payload += mac

    return bytes(payload)


def _split_payload(payload: bytes) -> typing.List[bytes]:
    """Split bigger encrypted messages (payload)"""
    max_package = _STD_PACKAGE_SIZE + _TAG_LEN

    if len(payload) > max_package:
        return [
            payload[i : i + max_package]
            for i in range(0, len(payload), max_package)
        ]

    return [payload]


def _decrypt_single(
    payloads: typing.List[bytes], idx: int, cipher_gen
) -> bytes:
    """Perform decryption on the single splitted payload"""
    payload = payloads[idx]

    cipher = cipher_gen(idx, idx == len(payloads) - 1)

    hmac_tag = payload[-_TAG_LEN:]
    encrypted_data = payload[:-_TAG_LEN]

    decrypted_data = cipher.decrypt_and_verify(encrypted_data, hmac_tag)
    return decrypted_data


def _get_cipher_provider(
    cipher_id: int,
) -> typing.Union[AesGcmCipherProvider, ChaCha20Poly1305CipherProvider, None]:
    """Generate cipher basing on the version byte"""
    if cipher_id == 0:
        return AesGcmCipherProvider()
    if cipher_id == 1:
        return ChaCha20Poly1305CipherProvider()
    return None


def decrypt(payload: bytes, password: str) -> bytes:
    """
    Decrypts data using AES-GCM or ChaCha20Poly1305 using a
    256-bit Argon2ID key. To see the original implementation in Go,
    check out the madmin-go library
    (https://github.com/minio/madmin-go/blob/main/encrypt.go#L38)
    """

    salt = payload[0:_SALT_END]
    aead_id = payload[_SALT_END:_AEAD_ID_END]
    nonce = payload[_AEAD_ID_END:_NONCE_END]
    encrypted_data = payload[_NONCE_END:]

    def cipher_gen(idx: int, last: bool):
        cipher_provider = _get_cipher_provider(aead_id[0])

        if cipher_provider is None:
            raise CryptoException("No valid cipher")

        key = _generate_key(password.encode(), salt)

        # Generate nonce with idx space
        padded_nonce = [0] * (_NONCE_LEN + 4)
        padded_nonce[:_NONCE_LEN] = nonce

        additional_data = _generate_additional_data(
            cipher_provider, key, bytes(padded_nonce)
        )
        if last:
            _mark_as_last(additional_data)

        additional_data = bytes(additional_data)

        # Append id to the nonce
        _update_nonce_id(padded_nonce, idx + 1)

        cipher = cipher_provider.get_cipher(key, bytes(padded_nonce))
        cipher.update(additional_data)
        return cipher

    # Split payloads to the array of buffers of the proper lengths
    payloads = _split_payload(encrypted_data)

    # Perform decryption
    decrypted_data = _decrypt_single(payloads, 0, cipher_gen)
    for idx in range(1, len(payloads)):
        decrypted_data += _decrypt_single(payloads, idx, cipher_gen)

    return decrypted_data


def _generate_additional_data(
    cipher_provider, key: bytes, padded_nonce: bytes
) -> typing.List[int]:
    """Generate additional data"""
    cipher = cipher_provider.get_cipher(key, padded_nonce)
    tag = cipher.digest()
    new_tag = [0] * 17
    new_tag[1:] = tag
    new_tag[0] = 0x00
    return new_tag


def _generate_key(password: bytes, salt: bytes) -> bytes:
    """Generate 256-bit Argon2ID key"""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=1,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
        version=19,
    )


def _mark_as_last(additional_data: typing.List[int]):
    """Mark additional data as the last in the sequence"""
    additional_data[0] = 0x80


def _update_nonce_id(padded_nonce: typing.List[int], idx: int):
    """Set nonce id (4 last bytes)"""
    idx_bytes = (idx).to_bytes(4, byteorder="little")
    padded_nonce[_NONCE_LEN:] = idx_bytes
