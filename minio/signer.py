# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015-2020 MinIO, Inc.
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
minio.signer
~~~~~~~~~~~~~~~

This module implements all helpers for AWS Signature version '4' support.

:copyright: (c) 2015 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

import hashlib
import hmac
import re
from collections import OrderedDict
from urllib.parse import SplitResult

from . import time
from .helpers import queryencode, sha256_hash

SIGN_V4_ALGORITHM = 'AWS4-HMAC-SHA256'
_MULTI_SPACE_REGEX = re.compile(r"( +)")


def _hmac_hash(key, data, hexdigest=False):
    """Return HMacSHA256 digest of given key and data."""

    hasher = hmac.new(key, data, hashlib.sha256)
    return hasher.hexdigest() if hexdigest else hasher.digest()


def _get_scope(date, region, service_name):
    """Get scope string."""
    return f"{time.to_signer_date(date)}/{region}/{service_name}/aws4_request"


def _get_canonical_headers(headers):
    """Get canonical headers."""

    canonical_headers = {}
    for key, values in headers.items():
        key = key.lower()
        if key not in (
                "authorization",
                "user-agent",
        ):
            values = values if isinstance(values, (list, tuple)) else [values]
            canonical_headers[key] = ",".join([
                _MULTI_SPACE_REGEX.sub(" ", value) for value in values
            ])

    canonical_headers = OrderedDict(sorted(canonical_headers.items()))
    signed_headers = ";".join(canonical_headers.keys())
    canonical_headers = "\n".join(
        [f"{key}:{value}" for key, value in canonical_headers.items()],
    )
    return canonical_headers, signed_headers


def _get_canonical_query_string(query):
    """Get canonical query string."""

    query = query or ""
    return "&".join(
        [
            "=".join(pair) for pair in sorted(
                [params.split("=") for params in query.split("&")],
            )
        ],
    )


def _get_canonical_request_hash(method, url, headers, content_sha256):
    """Get canonical request hash."""
    canonical_headers, signed_headers = _get_canonical_headers(headers)
    canonical_query_string = _get_canonical_query_string(url.query)

    # CanonicalRequest =
    #   HTTPRequestMethod + '\n' +
    #   CanonicalURI + '\n' +
    #   CanonicalQueryString + '\n' +
    #   CanonicalHeaders + '\n\n' +
    #   SignedHeaders + '\n' +
    #   HexEncode(Hash(RequestPayload))
    canonical_request = (
        f"{method}\n"
        f"{url.path or '/'}\n"
        f"{canonical_query_string}\n"
        f"{canonical_headers}\n\n"
        f"{signed_headers}\n"
        f"{content_sha256}"
    )
    return sha256_hash(canonical_request), signed_headers


def _get_string_to_sign(date, scope, canonical_request_hash):
    """Get string-to-sign."""
    return (
        f"AWS4-HMAC-SHA256\n{time.to_amz_date(date)}\n{scope}\n"
        f"{canonical_request_hash}"
    )


def _get_signing_key(secret_key, date, region, service_name):
    """Get signing key."""

    date_key = _hmac_hash(
        ("AWS4" + secret_key).encode(),
        time.to_signer_date(date).encode(),
    )
    date_region_key = _hmac_hash(date_key, region.encode())
    date_region_service_key = _hmac_hash(
        date_region_key, service_name.encode(),
    )
    return _hmac_hash(date_region_service_key, b"aws4_request")


def _get_signature(signing_key, string_to_sign):
    """Get signature."""

    return _hmac_hash(signing_key, string_to_sign.encode(), hexdigest=True)


def _get_authorization(access_key, scope, signed_headers, signature):
    """Get authorization."""
    return (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


def _sign_v4(
        service_name,
        method,
        url,
        region,
        headers,
        credentials,
        content_sha256,
        date,
):
    """Do signature V4 of given request for given service name."""

    scope = _get_scope(date, region, service_name)
    canonical_request_hash, signed_headers = _get_canonical_request_hash(
        method, url, headers, content_sha256,
    )
    string_to_sign = _get_string_to_sign(date, scope, canonical_request_hash)
    signing_key = _get_signing_key(
        credentials.secret_key, date, region, service_name,
    )
    signature = _get_signature(signing_key, string_to_sign)
    authorization = _get_authorization(
        credentials.access_key, scope, signed_headers, signature,
    )
    headers["Authorization"] = authorization
    return headers


def sign_v4_s3(
        method,
        url,
        region,
        headers,
        credentials,
        content_sha256,
        date,
):
    """Do signature V4 of given request for S3 service."""
    return _sign_v4(
        "s3",
        method,
        url,
        region,
        headers,
        credentials,
        content_sha256,
        date,
    )


def sign_v4_sts(
        method,
        url,
        region,
        headers,
        credentials,
        content_sha256,
        date,
):
    """Do signature V4 of given request for STS service."""
    return _sign_v4(
        "sts",
        method,
        url,
        region,
        headers,
        credentials,
        content_sha256,
        date,
    )


def _get_presign_canonical_request_hash(  # pylint: disable=invalid-name
        method, url, access_key, scope, date, expires,
):
    """Get canonical request hash for presign request."""
    x_amz_credential = queryencode(access_key + "/" + scope)
    canonical_headers, signed_headers = "host:" + url.netloc, "host"

    query = url.query+"&" if url.query else ""
    query += (
        f"X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential={x_amz_credential}"
        f"&X-Amz-Date={time.to_amz_date(date)}"
        f"&X-Amz-Expires={expires}"
        f"&X-Amz-SignedHeaders={signed_headers}"
    )
    parts = list(url)
    parts[3] = query
    url = SplitResult(*parts)

    canonical_query_string = _get_canonical_query_string(query)

    # CanonicalRequest =
    #   HTTPRequestMethod + '\n' +
    #   CanonicalURI + '\n' +
    #   CanonicalQueryString + '\n' +
    #   CanonicalHeaders + '\n\n' +
    #   SignedHeaders + '\n' +
    #   HexEncode(Hash(RequestPayload))
    canonical_request = (
        f"{method}\n"
        f"{url.path or '/'}\n"
        f"{canonical_query_string}\n"
        f"{canonical_headers}\n\n"
        f"{signed_headers}\n"
        f"UNSIGNED-PAYLOAD"
    )
    return sha256_hash(canonical_request), url


def presign_v4(
        method,
        url,
        region,
        credentials,
        date,
        expires,
):
    """Do signature V4 of given presign request."""

    scope = _get_scope(date, region, "s3")
    canonical_request_hash, url = _get_presign_canonical_request_hash(
        method, url, credentials.access_key, scope, date, expires,
    )
    string_to_sign = _get_string_to_sign(date, scope, canonical_request_hash)
    signing_key = _get_signing_key(credentials.secret_key, date, region, "s3")
    signature = _get_signature(signing_key, string_to_sign)

    parts = list(url)
    parts[3] = url.query + "&X-Amz-Signature=" + queryencode(signature)
    url = SplitResult(*parts)
    return url


def get_credential_string(access_key, date, region):
    """Get credential string of given access key, date and region."""
    return f"{access_key}/{time.to_signer_date(date)}/{region}/s3/aws4_request"


def post_presign_v4(data, secret_key, date, region):
    """Do signature V4 of given presign POST form-data."""
    return _get_signature(
        _get_signing_key(secret_key, date, region, "s3"),
        data,
    )
