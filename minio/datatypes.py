# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# 2020 MinIO, Inc.
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

# pylint: disable=too-many-lines

"""
Response of ListBuckets, ListObjects, ListObjectsV2 and ListObjectVersions API.
"""

from __future__ import absolute_import, annotations

import base64
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, List, Optional, Tuple, Type, TypeVar, Union, cast
from urllib.parse import unquote_plus
from xml.etree import ElementTree as ET

from urllib3._collections import HTTPHeaderDict

try:
    from urllib3.response import BaseHTTPResponse  # type: ignore[attr-defined]
except ImportError:
    from urllib3.response import HTTPResponse as BaseHTTPResponse

from .commonconfig import Tags
from .credentials import Credentials
from .helpers import check_bucket_name
from .signer import get_credential_string, post_presign_v4
from .time import from_iso8601utc, to_amz_date, to_iso8601utc
from .xml import find, findall, findtext

JSONDecodeError: type[ValueError]
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


@dataclass(frozen=True)
class Bucket:
    """Bucket information."""
    name: str
    creation_date: Optional[datetime]


A = TypeVar("A", bound="ListAllMyBucketsResult")


@dataclass(frozen=True)
class ListAllMyBucketsResult:
    """LissBuckets API result."""
    buckets: list[Bucket]

    @classmethod
    def fromxml(cls: Type[A], element: ET.Element) -> A:
        """Create new object with values from XML element."""
        element = cast(ET.Element, find(element, "Buckets", True))
        buckets = []
        elements = findall(element, "Bucket")
        for bucket in elements:
            name = cast(str, findtext(bucket, "Name", True))
            creation_date = findtext(bucket, "CreationDate")
            buckets.append(Bucket(
                name,
                from_iso8601utc(creation_date) if creation_date else None,
            ))
        return cls(buckets)


B = TypeVar("B", bound="Object")


@dataclass(frozen=True)
class Object:
    """Object information."""
    bucket_name: str
    object_name: Optional[str]
    last_modified: Optional[datetime] = None
    etag: Optional[str] = None
    size: Optional[int] = None
    metadata: Optional[Union[dict[str, str], HTTPHeaderDict]] = None
    version_id: Optional[str] = None
    is_latest: Optional[str] = None
    storage_class: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    content_type: Optional[str] = None
    is_delete_marker: bool = False
    tags: Optional[Tags] = None
    is_dir: bool = field(default=False, init=False)

    def __post_init__(self):
        object.__setattr__(
            self,
            "is_dir",
            bool(self.object_name and self.object_name.endswith("/")),
        )

    @classmethod
    def fromxml(
            cls: Type[B],
            element: ET.Element,
            bucket_name: str,
            is_delete_marker: bool = False,
            encoding_type: Optional[str] = None,
    ) -> B:
        """Create new object with values from XML element."""
        tag = findtext(element, "LastModified")
        last_modified = None if tag is None else from_iso8601utc(tag)

        tag = findtext(element, "ETag")
        etag = None if tag is None else tag.replace('"', "")

        tag = findtext(element, "Size")
        size = None if tag is None else int(tag)

        elem = find(element, "Owner")
        owner_id, owner_name = (
            (None, None) if elem is None
            else (findtext(elem, "ID"), findtext(elem, "DisplayName"))
        )

        elems: ET.Element | list = find(element, "UserMetadata") or []
        metadata: dict[str, str] = {}
        for child in elems:
            key = child.tag.split("}")[1] if "}" in child.tag else child.tag
            metadata[key] = child.text or ""

        object_name = cast(str, findtext(element, "Key", True))
        if encoding_type == "url":
            object_name = unquote_plus(object_name)

        tags_text = findtext(element, "UserTags")
        tags: Optional[Tags] = None
        if tags_text:
            tags = Tags.new_object_tags()
            tags.update(
                cast(
                    List[Tuple[Any, Any]],
                    [tokens.split("=") for tokens in tags_text.split("&")],
                ),
            )

        return cls(
            bucket_name=bucket_name,
            object_name=object_name,
            last_modified=last_modified,
            etag=etag,
            size=size,
            version_id=findtext(element, "VersionId"),
            is_latest=findtext(element, "IsLatest"),
            storage_class=findtext(element, "StorageClass"),
            owner_id=owner_id,
            owner_name=owner_name,
            metadata=metadata,
            is_delete_marker=is_delete_marker,
            tags=tags
        )


def parse_list_objects(
        response: BaseHTTPResponse,
        bucket_name: Optional[str] = None,
) -> tuple[list[Object], bool, Optional[str], Optional[str]]:
    """Parse ListObjects/ListObjectsV2/ListObjectVersions response."""
    element = ET.fromstring(response.data.decode())
    bucket_name = cast(str, findtext(element, "Name", True))
    encoding_type = findtext(element, "EncodingType")
    elements = findall(element, "Contents")
    objects = [
        Object.fromxml(tag, bucket_name, encoding_type=encoding_type)
        for tag in elements
    ]
    marker = objects[-1].object_name if objects else None

    elements = findall(element, "Version")
    objects += [
        Object.fromxml(tag, bucket_name, encoding_type=encoding_type)
        for tag in elements
    ]

    elements = findall(element, "CommonPrefixes")
    objects += [
        Object(
            bucket_name, unquote_plus(findtext(tag, "Prefix", True) or "")
            if encoding_type == "url" else findtext(tag, "Prefix", True)
        ) for tag in elements
    ]

    elements = findall(element, "DeleteMarker")
    objects += [
        Object.fromxml(tag, bucket_name, is_delete_marker=True,
                       encoding_type=encoding_type)
        for tag in elements
    ]

    is_truncated = (findtext(element, "IsTruncated") or "").lower() == "true"
    key_marker = findtext(element, "NextKeyMarker")
    if key_marker and encoding_type == "url":
        key_marker = unquote_plus(key_marker)
    version_id_marker = findtext(element, "NextVersionIdMarker")
    continuation_token = findtext(element, "NextContinuationToken")
    if key_marker is not None:
        continuation_token = key_marker
    if continuation_token is None:
        continuation_token = findtext(element, "NextMarker")
        if continuation_token and encoding_type == "url":
            continuation_token = unquote_plus(continuation_token)
    if continuation_token is None and is_truncated:
        continuation_token = marker
    return objects, is_truncated, continuation_token, version_id_marker


@dataclass(frozen=True)
class CompleteMultipartUploadResult:
    """CompleteMultipartUpload API result."""

    http_headers: HTTPHeaderDict
    bucket_name: Optional[str] = None
    object_name: Optional[str] = None
    location: Optional[str] = None
    etag: Optional[str] = None
    version_id: Optional[str] = None

    def __init__(self, response: BaseHTTPResponse):
        object.__setattr__(self, "http_headers", response.headers)
        element = ET.fromstring(response.data.decode())
        object.__setattr__(self, "bucket_name", findtext(element, "Bucket"))
        object.__setattr__(self, "object_name", findtext(element, "Key"))
        object.__setattr__(self, "location", findtext(element, "Location"))
        etag = findtext(element, "ETag")
        if etag:
            object.__setattr__(
                self,
                "etag",
                cast(str, etag).replace('"', ""),
            )
        object.__setattr__(
            self,
            "version_id",
            response.headers.get("x-amz-version-id"),
        )


C = TypeVar("C", bound="Part")


@dataclass(frozen=True)
class Part:
    """Part information of a multipart upload."""
    part_number: int
    etag: str
    last_modified: Optional[datetime] = None
    size: Optional[int] = None

    @classmethod
    def fromxml(cls: Type[C], element: ET.Element) -> C:
        """Create new object with values from XML element."""
        part_number = int(cast(str, findtext(element, "PartNumber", True)))
        etag = cast(str, findtext(element, "ETag", True))
        etag = etag.replace('"', "")
        tag = findtext(element, "LastModified")
        last_modified = None if tag is None else from_iso8601utc(tag)
        size = findtext(element, "Size")
        return cls(
            part_number=part_number,
            etag=etag,
            last_modified=last_modified,
            size=int(size) if size else None,
        )


@dataclass(frozen=True)
class ListPartsResult:
    """ListParts API result."""

    bucket_name: Optional[str] = None
    object_name: Optional[str] = None
    initiator_id: Optional[str] = None
    initiator_name: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    storage_class: Optional[str] = None
    part_number_marker: Optional[str] = None
    next_part_number_marker: Optional[str] = None
    max_parts: Optional[int] = None
    is_truncated: bool = False
    parts: list[Part] = field(default_factory=list)

    def __init__(self, response: BaseHTTPResponse):
        element = ET.fromstring(response.data.decode())
        object.__setattr__(self, "bucket_name", findtext(element, "Bucket"))
        object.__setattr__(self, "object_name", findtext(element, "Key"))
        tag = find(element, "Initiator")
        object.__setattr__(
            self,
            "initiator_id",
            None if tag is None else findtext(tag, "ID"),
        )
        object.__setattr__(
            self,
            "initiator_name",
            None if tag is None else findtext(tag, "DisplayName"),
        )
        tag = find(element, "Owner")
        object.__setattr__(
            self,
            "owner_id",
            None if tag is None else findtext(tag, "ID")
        )
        object.__setattr__(
            self,
            "owner_name",
            None if tag is None else findtext(tag, "DisplayName"),
        )
        object.__setattr__(
            self,
            "storage_class",
            findtext(element, "StorageClass"),
        )
        object.__setattr__(
            self,
            "part_number_marker",
            findtext(element, "PartNumberMarker"),
        )
        object.__setattr__(
            self,
            "next_part_number_marker",
            findtext(element, "NextPartNumberMarker"),
        )
        max_parts = findtext(element, "MaxParts")
        object.__setattr__(
            self,
            "max_parts",
            int(max_parts) if max_parts else None,
        )
        is_truncated = findtext(element, "IsTruncated")
        object.__setattr__(
            self,
            "is_truncated",
            is_truncated is not None and is_truncated.lower() == "true",
        )
        object.__setattr__(
            self,
            "parts",
            [Part.fromxml(tag) for tag in findall(element, "Part")],
        )


@dataclass(frozen=True)
class Upload:
    """ Upload information of a multipart upload."""

    object_name: str
    encoding_type: Optional[str] = None
    upload_id: Optional[str] = None
    initiator_id: Optional[str] = None
    initiator_name: Optional[str] = None
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    storage_class: Optional[str] = None
    initiated_time: Optional[datetime] = None

    def __init__(
            self, element: ET.Element, encoding_type: Optional[str] = None,
    ):
        object_name = cast(str, findtext(element, "Key", True))
        object.__setattr__(
            self,
            "object_name",
            unquote_plus(object_name) if encoding_type == "url"
            else object_name,
        )
        object.__setattr__(self, "encoding_type", encoding_type)
        object.__setattr__(self, "upload_id", findtext(element, "UploadId"))
        tag = find(element, "Initiator")
        object.__setattr__(
            self,
            "initiator_id",
            None if tag is None else findtext(tag, "ID"),
        )
        object.__setattr__(
            self,
            "initiator_name",
            None if tag is None else findtext(tag, "DisplayName"),
        )
        tag = find(element, "Owner")
        object.__setattr__(
            self,
            "owner_id",
            None if tag is None else findtext(tag, "ID"),
        )
        object.__setattr__(
            self,
            "owner_name",
            None if tag is None else findtext(tag, "DisplayName"),
        )
        object.__setattr__(
            self,
            "storage_class",
            findtext(element, "StorageClass"),
        )
        initiated_time = findtext(element, "Initiated")
        object.__setattr__(
            self,
            "initiated_time",
            from_iso8601utc(initiated_time) if initiated_time else None,
        )


@dataclass(frozen=True)
class ListMultipartUploadsResult:
    """ListMultipartUploads API result."""

    encoding_type: Optional[str] = None
    bucket_name: Optional[str] = None
    key_marker: Optional[str] = None
    upload_id_marker: Optional[str] = None
    next_key_marker: Optional[str] = None
    next_upload_id_marker: Optional[str] = None
    max_uploads: Optional[int] = None
    is_truncated: bool = False
    uploads: list[Upload] = field(default_factory=list)

    def __init__(self, response: BaseHTTPResponse):
        element = ET.fromstring(response.data.decode())
        encoding_type = findtext(element, "EncodingType")
        object.__setattr__(self, "encoding_type", encoding_type)
        object.__setattr__(
            self,
            "bucket_name",
            findtext(element, "Bucket"),
        )
        value = findtext(element, "KeyMarker")
        if value is not None and encoding_type == "url":
            value = unquote_plus(value)
        object.__setattr__(self, "key_marker", value)
        object.__setattr__(
            self,
            "upload_id_marker",
            findtext(element, "UploadIdMarker"),
        )
        value = findtext(element, "NextKeyMarker")
        if value is not None and encoding_type == "url":
            value = unquote_plus(value)
        object.__setattr__(self, "next_key_marker", value)
        object.__setattr__(
            self,
            "self._next_upload_id_marker",
            findtext(element, "NextUploadIdMarker"),
        )
        max_uploads = findtext(element, "MaxUploads")
        object.__setattr__(
            self,
            "max_uploads",
            int(max_uploads) if max_uploads else None,
        )
        is_truncated = findtext(element, "IsTruncated")
        object.__setattr__(
            self,
            "is_truncated",
            is_truncated is not None and is_truncated.lower() == "true",
        )
        object.__setattr__(
            self,
            "uploads",
            [
                Upload(tag, encoding_type)
                for tag in findall(element, "Upload")
            ],
        )


_RESERVED_ELEMENTS = (
    "bucket",
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "policy",
    "x-amz-signature",
)
_EQ = "eq"
_STARTS_WITH = "starts-with"
_ALGORITHM = "AWS4-HMAC-SHA256"


def _trim_dollar(value: str) -> str:
    """Trim dollar character if present."""
    return value[1:] if value.startswith("$") else value


class PostPolicy:
    """
    Post policy information to be used to generate presigned post policy
    form-data. Condition elements and respective condition for Post policy
    is available at
    https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html#sigv4-PolicyConditions
    """

    def __init__(self, bucket_name: str, expiration: datetime):
        check_bucket_name(bucket_name)
        if not isinstance(expiration, datetime):
            raise ValueError("expiration must be datetime type")
        self._bucket_name = bucket_name
        self._expiration = expiration
        self._conditions: OrderedDict = OrderedDict()
        self._conditions[_EQ] = OrderedDict()
        self._conditions[_STARTS_WITH] = OrderedDict()
        self._lower_limit: Optional[int] = None
        self._upper_limit: Optional[int] = None

    def add_equals_condition(self, element: str, value: str):
        """Add equals condition of an element and value."""
        if not element:
            raise ValueError("condition element cannot be empty")
        element = _trim_dollar(element)
        if (
                element in [
                    "success_action_redirect",
                    "redirect",
                    "content-length-range",
                ]
        ):
            raise ValueError(element + " is unsupported for equals condition")
        if element in _RESERVED_ELEMENTS:
            raise ValueError(element + " cannot be set")
        self._conditions[_EQ][element] = value

    def remove_equals_condition(self, element: str):
        """Remove previously set equals condition of an element."""
        if not element:
            raise ValueError("condition element cannot be empty")
        self._conditions[_EQ].pop(element)

    def add_starts_with_condition(self, element: str, value: str):
        """
        Add starts-with condition of an element and value. Value set to empty
        string does matching any content condition.
        """
        if not element:
            raise ValueError("condition element cannot be empty")
        element = _trim_dollar(element)
        if (
                element in ["success_action_status", "content-length-range"] or
                (
                    element.startswith("x-amz-") and
                    not element.startswith("x-amz-meta-")
                )
        ):
            raise ValueError(
                f"{element} is unsupported for starts-with condition",
            )
        if element in _RESERVED_ELEMENTS:
            raise ValueError(element + " cannot be set")
        self._conditions[_STARTS_WITH][element] = value

    def remove_starts_with_condition(self, element: str):
        """Remove previously set starts-with condition of an element."""
        if not element:
            raise ValueError("condition element cannot be empty")
        self._conditions[_STARTS_WITH].pop(element)

    def add_content_length_range_condition(  # pylint: disable=invalid-name
            self, lower_limit: int, upper_limit: int):
        """Add content-length-range condition with lower and upper limits."""
        if lower_limit < 0:
            raise ValueError("lower limit cannot be negative number")
        if upper_limit < 0:
            raise ValueError("upper limit cannot be negative number")
        if lower_limit > upper_limit:
            raise ValueError("lower limit cannot be greater than upper limit")
        self._lower_limit = lower_limit
        self._upper_limit = upper_limit

    def remove_content_length_range_condition(  # pylint: disable=invalid-name
            self):
        """Remove previously set content-length-range condition."""
        self._lower_limit = None
        self._upper_limit = None

    def form_data(self, creds: Credentials, region: str):
        """
        Return form-data of this post policy. The returned dict contains
        x-amz-algorithm, x-amz-credential, x-amz-security-token, x-amz-date,
        policy and x-amz-signature.
        """
        if not isinstance(creds, Credentials):
            raise ValueError("credentials must be Credentials type")
        if not region:
            raise ValueError("region cannot be empty")
        if (
                "key" not in self._conditions[_EQ] and
                "key" not in self._conditions[_STARTS_WITH]
        ):
            raise ValueError("key condition must be set")

        policy: OrderedDict = OrderedDict()
        policy["expiration"] = to_iso8601utc(self._expiration)
        policy["conditions"] = [[_EQ, "$bucket", self._bucket_name]]
        for cond_key, conditions in self._conditions.items():
            for key, value in conditions.items():
                policy["conditions"].append([cond_key, "$"+key, value])
        if self._lower_limit is not None and self._upper_limit is not None:
            policy["conditions"].append(
                ["content-length-range", self._lower_limit, self._upper_limit],
            )
        utcnow = datetime.utcnow()
        credential = get_credential_string(creds.access_key, utcnow, region)
        amz_date = to_amz_date(utcnow)
        policy["conditions"].append([_EQ, "$x-amz-algorithm", _ALGORITHM])
        policy["conditions"].append([_EQ, "$x-amz-credential", credential])
        if creds.session_token:
            policy["conditions"].append(
                [_EQ, "$x-amz-security-token", creds.session_token],
            )
        policy["conditions"].append([_EQ, "$x-amz-date", amz_date])

        policy_encoded = base64.b64encode(
            json.dumps(policy).encode(),
        ).decode("utf-8")
        signature = post_presign_v4(
            policy_encoded, creds.secret_key, utcnow, region,
        )
        form_data = {
            "x-amz-algorithm": _ALGORITHM,
            "x-amz-credential": credential,
            "x-amz-date": amz_date,
            "policy": policy_encoded,
            "x-amz-signature": signature,
        }
        if creds.session_token:
            form_data["x-amz-security-token"] = creds.session_token
        return form_data

    @property
    def bucket_name(self) -> str:
        """Get bucket name."""
        return self._bucket_name


def parse_copy_object(
        response: BaseHTTPResponse,
) -> tuple[str, Optional[datetime]]:
    """Parse CopyObject/UploadPartCopy response."""
    element = ET.fromstring(response.data.decode())
    etag = cast(str, findtext(element, "ETag", True)).replace('"', "")
    last_modified = findtext(element, "LastModified")
    return etag, from_iso8601utc(last_modified) if last_modified else None


class EventIterable:
    """Context manager friendly event iterable."""

    def __init__(self, func):
        self._func = func
        self._response = None

    def _close_response(self):
        """Close response."""
        if self._response:
            self._response.close()
            self._response.release_conn()
            self._response = None

    def __iter__(self):
        return self

    def _get_records(self):
        """Get event records from response stream."""
        try:
            line = self._response.readline().strip()
            if not line:
                return None
            if hasattr(line, 'decode'):
                line = line.decode()
            event = json.loads(line)
            if event['Records']:
                return event
        except (StopIteration, JSONDecodeError):
            self._close_response()
        return None

    def __next__(self):
        records = None
        while not records:
            if not self._response or self._response.closed:
                self._response = self._func()
            records = self._get_records()
        return records

    def __enter__(self):
        return self

    def __exit__(self, exc_type, value, traceback):
        self._close_response()


@dataclass(frozen=True)
class PeerSite:
    """Represents a cluster/site to be added to the set of replicated sites."""
    name: str
    endpoint: str
    access_key: str
    secret_key: str

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "endpoints": self.endpoint,
            "accessKey": self.access_key,
            "secretKey": self.secret_key,
        }


@dataclass(frozen=True)
class SiteReplicationStatusOptions:
    """Represents site replication status options."""
    ENTITY_TYPE = Enum(
        "ENTITY_TYPE",
        {
            "BUCKET": "bucket",
            "POLICY": "policy",
            "USER": "user",
            "GROUP": "group",
        },
    )
    buckets: bool = False
    policies: bool = False
    users: bool = False
    groups: bool = False
    metrics: bool = False
    show_deleted: bool = False
    entity: Optional[str] = None
    entity_value: Optional[str] = None

    def to_query_params(self) -> dict[str, str]:
        """Convert this options to query parameters."""
        params = {
            "buckets": str(self.buckets).lower(),
            "policies": str(self.policies).lower(),
            "users": str(self.users).lower(),
            "groups": str(self.groups).lower(),
            "metrics": str(self.metrics).lower(),
            "showDeleted": str(self.show_deleted).lower(),
        }
        if self.entity and self.entity_value:
            params["entity"] = self.entity
            params["entityvalue"] = self.entity_value
        return params


@dataclass(frozen=True)
class PeerInfo:
    """Site replication peer information."""
    deployment_id: str
    endpoint: str
    bucket_bandwidth_limit: str
    bucket_bandwidth_set: str
    name: Optional[str] = None
    sync_status: Optional[str] = None
    bucket_bandwidth_updated_at: Optional[datetime] = None

    def to_dict(self):
        """Converts peer information to dictionary."""
        data = {
            "endpoint": self.endpoint,
            "deploymentID": self.deployment_id,
            "defaultbandwidth": {
                "bandwidthLimitPerBucket": self.bucket_bandwidth_limit,
                "set": self.bucket_bandwidth_set,
            },
        }
        if self.name:
            data["name"] = self.name
        if self.sync_status is not None:
            data["sync"] = "enable" if self.sync_status else "disable"
        if self.bucket_bandwidth_updated_at:
            data["defaultbandwidth"]["updatedAt"] = to_iso8601utc(
                self.bucket_bandwidth_updated_at,
            )
        return data
