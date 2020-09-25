# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015 MinIO, Inc.
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
minio.definitions
~~~~~~~~~~~~~~~

This module contains the primary objects that power MinIO.

:copyright: (c) 2015 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from urllib.parse import urlsplit

from .helpers import queryencode, quote, url_replace


def _extract_region(host):
    """Extract region from Amazon S3 host."""

    tokens = host.split(".")
    token = tokens[1]

    # If token is "dualstack", then region might be in next token.
    if token == "dualstack":
        token = tokens[2]

    # If token is equal to "amazonaws", region is not passed in the host.
    if token == "amazonaws":
        return None

    # Return token as region.
    return token


class BaseURL:
    """Base URL of S3 endpoint."""

    def __init__(self, endpoint, region):
        url = urlsplit(endpoint)
        host = url.hostname

        if url.scheme.lower() not in ["http", "https"]:
            raise ValueError("scheme in endpoint must be http or https")

        url = url_replace(url, scheme=url.scheme.lower())

        if url.path and url.path != "/":
            raise ValueError("path in endpoint is not allowed")

        url = url_replace(url, path="")

        if url.query:
            raise ValueError("query in endpoint is not allowed")

        if url.fragment:
            raise ValueError("fragment in endpoint is not allowed")

        try:
            url.port
        except ValueError as exc:
            raise ValueError("invalid port") from exc

        if url.username:
            raise ValueError("username in endpoint is not allowed")

        if url.password:
            raise ValueError("password in endpoint is not allowed")

        if (
                (url.scheme == "http" and url.port == 80) or
                (url.scheme == "https" and url.port == 443)
        ):
            url = url_replace(url, netloc=host)

        self._accelerate_host_flag = host.startswith("s3-accelerate.")
        self._is_aws_host = (
            (
                host.startswith("s3.") or self._accelerate_host_flag
            ) and
            (
                host.endswith(".amazonaws.com") or
                host.endswith(".amazonaws.com.cn")
            )
        )
        self._virtual_style_flag = (
            self._is_aws_host or host.endswith("aliyuncs.com")
        )

        region_in_host = None
        if self._is_aws_host:
            is_aws_china_host = host.endswith(".cn")
            url = url_replace(
                url,
                netloc=(
                    "amazonaws.com.cn"
                    if is_aws_china_host else "amazonaws.com"
                ),
            )
            region_in_host = _extract_region(host)

            if is_aws_china_host and not region_in_host and not region:
                raise ValueError(
                    "region missing in Amazon S3 China endpoint {0}".format(
                        endpoint,
                    ),
                )
            self._dualstack_host_flag = ".dualstack." in host
        else:
            self._accelerate_host_flag = False

        self._url = url
        self._region = region or region_in_host

    @property
    def region(self):
        """Get region."""
        return self._region

    @property
    def is_https(self):
        """Check if scheme is HTTPS."""
        return self._url.scheme == "https"

    @property
    def host(self):
        """Get hostname."""
        return self._url.netloc

    @property
    def is_aws_host(self):
        """Check if URL points to AWS host."""
        return self._is_aws_host

    @property
    def accelerate_host_flag(self):
        """Check if URL points to AWS accelerate host."""
        return self._accelerate_host_flag

    @accelerate_host_flag.setter
    def accelerate_host_flag(self, flag):
        """Check if URL points to AWS accelerate host."""
        if self._is_aws_host:
            self._accelerate_host_flag = flag

    @property
    def dualstack_host_flag(self):
        """Check if URL points to AWS dualstack host."""
        return self._dualstack_host_flag

    @dualstack_host_flag.setter
    def dualstack_host_flag(self, flag):
        """Check to use virtual style or not."""
        if self._is_aws_host:
            self._dualstack_host_flag = flag

    @property
    def virtual_style_flag(self):
        """Check to use virtual style or not."""
        return self._virtual_style_flag

    @virtual_style_flag.setter
    def virtual_style_flag(self, flag):
        """Check to use virtual style or not."""
        self._virtual_style_flag = flag

    def build(
            self, method, region,
            bucket_name=None, object_name=None, query_params=None,
    ):
        """Build URL for given information."""

        if not bucket_name and object_name:
            raise ValueError(
                "empty bucket name for object name {0}".format(object_name),
            )

        query = []
        for key, values in sorted((query_params or {}).items()):
            values = values if isinstance(values, (list, tuple)) else [values]
            query += [
                "{0}={1}".format(queryencode(key), queryencode(value))
                for value in sorted(values)
            ]
        url = url_replace(self._url, query="&".join(query))
        host = self._url.netloc

        if not bucket_name:
            url = url_replace(url, path="/")
            return (
                url_replace(url, netloc="s3." + region + "." + host)
                if self._is_aws_host else url
            )

        enforce_path_style = (
            # CreateBucket API requires path style in Amazon AWS S3.
            (method == "PUT" and not object_name and not query_params) or

            # GetBucketLocation API requires path style in Amazon AWS S3.
            (query_params and query_params.get("location")) or

            # Use path style for bucket name containing '.' which causes
            # SSL certificate validation error.
            ("." in bucket_name and self._url.scheme == "https")
        )

        if self._is_aws_host:
            s3_domain = "s3."
            if self._accelerate_host_flag:
                if "." in bucket_name:
                    raise ValueError(
                        (
                            "bucket name '{0}' with '.' is not allowed "
                            "for accelerated endpoint"
                        ).format(bucket_name),
                    )

                if not enforce_path_style:
                    s3_domain = "s3-accelerate."

            dual_stack = "dualstack." if self._dualstack_host_flag else ""
            endpoint = s3_domain + dual_stack
            if enforce_path_style or not self._accelerate_host_flag:
                endpoint += region + "."
            host = endpoint + host

        if enforce_path_style or not self._virtual_style_flag:
            url = url_replace(url, netloc=host)
            url = url_replace(url, path="/" + bucket_name)
        else:
            url = url_replace(
                url,
                netloc=bucket_name + "." + host,
                path="/",
            )

        if object_name:
            path = url.path
            path += ("" if path.endswith("/") else "/") + quote(object_name)
            url = url_replace(url, path=path)

        return url


class Bucket:
    """
    A bucket metadata :class:`Bucket <Bucket>`.

    :param name: Bucket name.
    :param created: Bucket creation date.
    """

    def __init__(self, name, created):
        self.name = name
        self.creation_date = created

    def __str__(self):
        return "<Bucket: {0} {1}>".format(self.name, self.creation_date)


class Object:
    """
    A object metadata :class:`Object <Object>`.

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param last_modified: Object when it was last modified on server.
    :param etag: ETag saved on server for the object_name.
    :param size: Size of the object on server.
    :param content_type: Optional parameter indicating content type.
    :param is_dir: Optional parameter differentiating object prefixes.
    :param metadata: Optional parameter contains all the custom metadata.
    """

    def __init__(self, bucket_name,  # pylint: disable=too-many-arguments
                 object_name,
                 last_modified=None, etag='',
                 size=0, content_type=None, is_dir=False, metadata=None,
                 version_id=None, is_latest=None, storage_class=None,
                 owner_id=None, owner_name=None, delete_marker=False):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.last_modified = last_modified
        self.etag = etag
        self.size = size
        self.content_type = content_type
        self.is_dir = is_dir
        self.metadata = metadata
        self.version_id = version_id
        self.is_latest = is_latest
        self.storage_class = storage_class
        self.owner_id = owner_id
        self.owner_name = owner_name
        self.delete_marker = delete_marker

    def __str__(self):
        return (
            "<Object: "
            "bucket_name: {bucket_name} "
            "object_name: {object_name} "
            "version_id: {version_id} "
            "last_modified: {last_modified} "
            "etag: {etag} "
            "size: {size} "
            "content_type: {content_type} "
            "is_dir: {is_dir} "
            "metadata: {metadata} "
            ">"
        ).format(
            bucket_name=self.bucket_name,
            object_name=self.object_name.encode("utf-8"),
            version_id=self.version_id,
            last_modified=self.last_modified,
            etag=self.etag,
            size=self.size,
            content_type=self.content_type,
            is_dir=self.is_dir,
            metadata=self.metadata,
        )


class MultipartUploadResult:
    """
    A completed multipart upload metadata
         :class:`MultipartUploadResult <MultipartUploadResult>`.

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param location: Object uploaded location.
    :param etag: Object final etag.
    """

    def __init__(self, bucket_name, object_name, location, etag):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.location = location
        self.etag = etag

    def __str__(self):
        string_format = ("<IncompleteUpload: bucket_name: {0}"
                         " object_name: {1} location: {2} etag: {3}>")
        return string_format.format(self.bucket_name, self.object_name,
                                    self.location, self.etag)


class CopyObjectResult:
    """
    A complete copy object operation metadata.
         :class:`CopyObjectResult <CopyObjectResult>`.

    :param bucket_name: Bucket name.
    :param object_name: Object name.
    :param etag: ETag saved on the server computed for object_name.
    :param last_modified: Object when it was last modified on server.
    """

    def __init__(self, bucket_name, object_name, etag, last_modified):
        self.bucket_name = bucket_name
        self.object_name = object_name
        self.etag = etag
        self.last_modified = last_modified

    def __str__(self):
        string_format = ("<CopyObjectResult: bucket_name: {0}"
                         " object_name: {1} etag: {2} last_modified: {3}>")
        return string_format.format(self.bucket_name, self.object_name,
                                    self.etag, self.last_modified)


class Upload:
    """ Upload information of a multipart upload."""

    def __init__(self, root):
        self.object_name = root.get_urldecoded_elem_text("Key")
        self.upload_id = root.get_child_text("UploadId")
        self.initiator_id, self.initator_name = (
            root.find("Initiator").get_child_text("ID", strict=False),
            root.find("Initiator").get_child_text(
                "DisplayName", strict=False,
            ),
        ) if root.find("Initiator") else (None, None)
        self.owner_id, self.owner_name = (
            root.find("Owner").get_child_text("ID", strict=False),
            root.find("Owner").get_child_text("DisplayName", strict=False),
        ) if root.find("Owner") else (None, None)
        self.storage_class = root.get_child_text("StorageClass")
        self.initiated_time = root.get_localized_time_elem("Initiated")


class ListMultipartUploadsResult:
    """ListMultipartUploads API result."""

    def __init__(self, root):
        self.bucket_name = root.get_child_text("Bucket")
        self.key_marker = root.get_urldecoded_elem_text(
            "KeyMarker", strict=False,
        )
        self.upload_id_marker = root.get_child_text(
            "UploadIdMarker", strict=False,
        )
        self.next_key_marker = root.get_urldecoded_elem_text(
            "NextKeyMarker", strict=False,
        )
        self.next_upload_id_marker = root.get_child_text(
            "NextUploadIdMarker", strict=False,
        )
        self.max_uploads = root.get_int_elem("MaxUploads")
        self._is_truncated = (
            root.get_child_text("IsTruncated", strict=False).lower() == "true"
        )
        self.uploads = [
            Upload(upload_element) for upload_element in root.findall("Upload")
        ]


class Part:
    """Part information of a multipart upload."""

    def __init__(self, part_number=None, etag=None, root=None):
        if not root and not part_number and not etag:
            raise ValueError("part_number/etag or root element must be passed")

        if root:
            part_number = root.get_child_text("PartNumber")
            etag = root.get_child_text("ETag")
            self.last_modified = root.get_localized_time_elem("LastModified")
            self.size = root.get_int_elem("Size")
        self.part_number = part_number
        self.etag = etag


class ListPartsResult:
    """ListParts API result."""

    def __init__(self, root):
        self.bucket_name = root.get_child_text("Bucket")
        self.object_name = root.get_child_text("Key")
        self.initiator_id, self.initator_name = (
            root.find("Initiator").get_child_text("ID", strict=False),
            root.find("Initiator").get_child_text(
                "DisplayName", strict=False,
            ),
        ) if root.find("Initiator") else (None, None)
        self.owner_id, self.owner_name = (
            root.find("Owner").get_child_text("ID", strict=False),
            root.find("Owner").get_child_text("DisplayName", strict=False),
        ) if root.find("Owner") else (None, None)
        self.storage_class = root.get_child_text("StorageClass")
        self.part_number_marker = root.get_int_elem("PartNumberMarker")
        self.next_part_number_marker = root.get_int_elem(
            "NextPartNumberMarker",
        )
        self.max_parts = root.get_int_elem("MaxParts")
        self._is_truncated = (
            root.get_child_text("IsTruncated", strict=False).lower() == "true"
        )
        self.parts = [
            Part(part_element) for part_element in root.findall("Part")
        ]


class VersioningConfig:
    """Bucket versioning configuration."""

    def __init__(self, status, mfa_delete=None):
        if status:
            status = status.title()
        if status not in ["", "Enabled", "Suspended"]:
            raise ValueError("status must be empty, Enabled or Suspended.")
        self._status = status
        self._mfa_delete = mfa_delete

    @property
    def status(self):
        """Get status."""
        return self._status or "Off"

    @property
    def mfa_delete(self):
        """Get MFA delete."""
        return self._mfa_delete
