# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`minio-py` is the MinIO Python client SDK for Amazon S3-compatible object storage. It is a pure-Python library (Python 3.10+) with no MinIO-specific build step; `urllib3` is the only transport dependency. It is published to PyPI as `minio`.

## Common commands

```sh
make check                # pylint + isort --diff + autopep8 --diff (lint only, no writes) + mypy
make apply                # auto-fix: isort + autopep8 --in-place
make tests                # check, then unit tests (pytest), then functional tests
make getdeps              # install dev/lint dependencies
./check.sh                # like `make check` but applies fixes first, also lints examples/ and tests/unit/

pytest                                          # all unit tests
pytest tests/unit/minio_test.py                 # one test file
pytest tests/unit/minio_test.py::ValidBucketName::test_bucket_name   # one test case

bash run_functional_tests.sh   # downloads a minio server binary, runs it, then runs functional tests
```

Functional tests live in `tests/functional/tests.py` (a single script, not pytest) and require a running S3 server. `run_functional_tests.sh` will download and start a local `minio` server if `SERVER_ENDPOINT` is unset; otherwise it targets the server configured via `SERVER_ENDPOINT`, `ACCESS_KEY`, `SECRET_KEY`, `ENABLE_HTTPS`, `MINT_MODE`.

The lint stack must pass clean: `pylint`, `isort`, `autopep8` (PEP 8), and `mypy minio` (the package ships `py.typed` and is fully type-annotated). Run `make apply` before committing to satisfy isort/autopep8.

## Architecture

Two public entry points are exported from `minio/__init__.py`:
- `Minio` (in `minio/minio.py`) — the S3 data-plane client. One ~6400-line class with one method per S3 operation (`put_object`, `get_object`, `list_objects`, `copy_object`, presigned URLs, bucket policy/lifecycle/replication/tagging/notification/versioning/encryption, etc.). All requests funnel through internal `_execute`/`_url_open` helpers that handle signing, retries, region resolution, and error parsing.
- `MinioAdmin` (in `minio/minioadmin.py`) — the admin-plane client for the MinIO admin REST API (users, policies, KMS, config, etc.), dispatched via the `_COMMAND` enum.

Supporting modules (each is single-responsibility; read these before changing client behavior):
- `signer.py` — AWS SigV4 request signing (headers, query/presign, streaming).
- `credentials/providers.py` — pluggable credential `Provider` chain (static, env, AWS config/IAM, STS AssumeRole/WebIdentity/LDAP/ClientGrants/Certificate). `Minio(credentials=...)` takes any `Provider`.
- `helpers.py` — `BaseURL` (endpoint/region/virtual-host/dualstack/accelerate URL construction), name validation, multipart sizing constants, threaded I/O helpers.
- `models.py` — ~50 request/response dataclasses (bucket configs, object info, select, etc.).
- `xml.py` — S3 XML marshalling/unmarshalling built on ElementTree; most config objects implement `fromxml`/`toxml`.
- `args.py` — argument-holder classes shared across operations. `error.py` — `S3Error`/`ServerError`/`InvalidResponseError`. `sse.py` / `crypto.py` — server-side encryption and credential-file crypto. `checksum.py` — CRC/SHA checksums. `time.py`, `compat.py` — time formatting and Py compat shims.
- `rdma.py` — **opt-in** RDMA / NVIDIA GPUDirect Storage acceleration for `put_object`/`get_object`, dispatched to `libminiocpp.so` via ctypes when `Minio(enable_rdma=True)`. The SDK stays pure-Python unless this path is used; see `examples/*_rdma.py`.

## Tests

- Unit tests (`tests/unit/*_test.py`) use `unittest.TestCase` (run under pytest) and mock HTTP via `tests/unit/minio_mocks.py` (`MockResponse`) — no network. File naming convention is `<area>_test.py`.
- Functional tests (`tests/functional/tests.py`) exercise a real server end-to-end.

## Conventions

- Public client methods are keyword-argument oriented and validate inputs eagerly (bucket/object name checks, type checks) before issuing requests.
- New S3 config types follow the existing `models.py` dataclass + `xml.py` `fromxml`/`toxml` pattern, with a matching `*_test.py`.
- `examples/` holds one runnable script per API; keep them in sync when adding/changing public methods.
