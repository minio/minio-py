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

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES, ChaCha20_Poly1305

_NONCE_LEN = 8
_SALT_LEN = 32


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
        cipher_provider, key, bytes(padded_nonce))

    padded_nonce[8] = 0x01
    padded_nonce = bytes(padded_nonce)

    cipher = cipher_provider.get_cipher(key, padded_nonce)
    cipher.update(additional_data)
    encrypted_data, mac = cipher.encrypt_and_digest(payload)

    payload = salt
    payload += bytes([0x00])
    payload += nonce
    payload += encrypted_data
    payload += mac

    return bytes(payload)


def decrypt(payload: bytes, password: str) -> bytes:
    """
    Decrypts data using AES-GCM or ChaCha20Poly1305 using a
    256-bit Argon2ID key. To see the original implementation in Go,
    check out the madmin-go library
    (https://github.com/minio/madmin-go/blob/main/encrypt.go#L38)
    """
    pos = 0
    salt = payload[pos:pos+_SALT_LEN]
    pos += _SALT_LEN

    cipher_id = payload[pos]
    if cipher_id == 0:
        cipher_provider = AesGcmCipherProvider()
    elif cipher_id == 1:
        cipher_provider = ChaCha20Poly1305CipherProvider()
    else:
        return None

    pos += 1

    nonce = payload[pos:pos+_NONCE_LEN]
    pos += _NONCE_LEN

    encrypted_data = payload[pos:-16]
    hmac_tag = payload[-16:]

    key = _generate_key(password.encode(), salt)

    padded_nonce = [0] * 12
    padded_nonce[:_NONCE_LEN] = nonce

    additional_data = _generate_additional_data(
        cipher_provider, key, bytes(padded_nonce))
    padded_nonce[8] = 1

    cipher = cipher_provider.get_cipher(key, bytes(padded_nonce))

    cipher.update(additional_data)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, hmac_tag)

    return decrypted_data


def _generate_additional_data(cipher_provider, key: bytes,
                              padded_nonce: bytes) -> bytes:
    """Generate additional data"""
    cipher = cipher_provider.get_cipher(key, padded_nonce)
    tag = cipher.digest()
    new_tag = [0] * 17
    new_tag[1:] = tag
    new_tag[0] = 0x80
    return bytes(new_tag)


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
        version=19
    )
