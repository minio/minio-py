# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2024] - [2026] MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the RDMA dispatch path. The libminiocpp.so loader is
mocked so these tests run on any host without RDMA hardware or libraries."""

from __future__ import annotations

import ctypes
import unittest
from unittest import mock

from minio.minio import Minio


class _FakeLib:
    """Mimics the ctypes.CDLL surface that minio.rdma uses."""

    def __init__(self):
        self.put_calls = []
        self.get_calls = []

    def _stub(self, kind):
        def call(*args):
            if kind == "client_new":
                return 0x1234
            if kind == "put":
                self.put_calls.append(args)
                etag = args[-2]
                checksum = args[-1]
                ctypes.memmove(etag, b'"deadbeef"\0', 11)
                ctypes.memmove(checksum, b'crc64-stub\0', 11)
                return ctypes.c_ssize_t(args[4]).value  # size arg
            if kind == "get":
                self.get_calls.append(args)
                return ctypes.c_ssize_t(args[4]).value
            if kind == "alloc":
                return 0
            if kind == "available":
                return 1
            return 0
        return call

    def __getattr__(self, name):
        if name == "miniocpp_client_new":
            return self._stub("client_new")
        if name == "miniocpp_put_object":
            return self._stub("put")
        if name == "miniocpp_get_object":
            return self._stub("get")
        if name == "miniocpp_rdma_available":
            return self._stub("available")
        if name == "miniocpp_alloc_aligned":
            return self._stub("alloc")
        if name == "miniocpp_free_aligned":
            return lambda *a: None
        if name == "miniocpp_client_free":
            return lambda *a: None
        if name == "miniocpp_last_error":
            return lambda: None
        raise AttributeError(name)


class RDMADispatchTest(unittest.TestCase):
    def setUp(self):
        import minio.rdma as rdma_mod
        self._fake = _FakeLib()
        # Stash the original loader and swap in our fake.
        self._orig = rdma_mod._LIB
        rdma_mod._LIB = self._fake
        # Patch ctypes argtype binding (loader sets these on a real CDLL only).
        # Our fake just exposes attributes by name.

    def tearDown(self):
        import minio.rdma as rdma_mod
        rdma_mod._LIB = self._orig

    def test_put_object_dispatches_to_rdma(self):
        client = Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=True,
        )
        buf = bytearray(b"x" * 1024)
        resp = client.put_object(
            bucket_name="bucket",
            object_name="object",
            data=buf,
            length=len(buf),
        )
        self.assertEqual(resp.etag, "deadbeef")
        self.assertEqual(len(self._fake.put_calls), 1)

    def test_get_object_dispatches_to_rdma(self):
        client = Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=True,
        )
        dst = bytearray(2048)
        n = client.get_object(
            bucket_name="bucket",
            object_name="object",
            into=dst,
            length=len(dst),
        )
        self.assertEqual(n, 2048)
        self.assertEqual(len(self._fake.get_calls), 1)

    def test_rdma_off_skips_dispatch(self):
        client = Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=False,
        )
        # With enable_rdma=False, passing a buffer should fall through to the
        # HTTP path; calling it without a real server raises a network error,
        # not an RDMA error. We only verify the dispatch never ran.
        with self.assertRaises(Exception):
            client.put_object(
                bucket_name="bucket",
                object_name="object",
                data=bytearray(b"x"),
                length=1,
            )
        self.assertEqual(len(self._fake.put_calls), 0)


if __name__ == "__main__":
    unittest.main()
