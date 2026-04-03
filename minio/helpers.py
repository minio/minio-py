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

"""Utility functions and classes."""

from __future__ import annotations

import platform
import re
import urllib.parse
from queue import Queue
from threading import BoundedSemaphore, Lock, Thread
from typing import Mapping, Optional

from . import __title__, __version__
from .compat import HTTPHeaderDict, HTTPQueryDict, quote

_DEFAULT_USER_AGENT = (
    f"MinIO ({platform.system()}; {platform.machine()}) "
    f"{__title__}/{__version__}"
)

MAX_MULTIPART_COUNT = 10000  # 10,000 parts
MAX_PART_SIZE = 5 * 1024 * 1024 * 1024  # 5GiB
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB
MAX_MULTIPART_OBJECT_SIZE = MAX_PART_SIZE * MAX_MULTIPART_COUNT  # 48.828125TiB

_AWS_S3_PREFIX = (
    r'^(((bucket\.|accesspoint\.)'
    r'vpce(-(?!_)[a-z_\d]+(?<!-)(?<!_))+\.s3\.)|'
    r'((?!s3)(?!-)(?!_)[a-z_\d-]{1,63}(?<!-)(?<!_)\.)'
    r's3-control(-(?!_)[a-z_\d]+(?<!-)(?<!_))*\.|'
    r'([a-z\d\-]+-[0-9]{12})\.s3-accesspoint\.|'
    r'(s3(-(?!_)[a-z_\d]+(?<!-)(?<!_))*\.))'
)

_BUCKET_NAME_REGEX = re.compile(r'^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$')
_OLD_BUCKET_NAME_REGEX = re.compile(
    r'^[a-z0-9][a-z0-9_\.\-\:]{1,61}[a-z0-9]$',
    re.IGNORECASE,
)
_IPV4_REGEX = re.compile(
    r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}'
    r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$'
)
_HOSTNAME_REGEX = re.compile(
    r'^((?!-)(?!_)[a-z_\d-]{1,63}(?<!-)(?<!_)\.)*'
    r'((?!_)(?!-)[a-z_\d-]{1,63}(?<!-)(?<!_))$',
    re.IGNORECASE,
)
_AWS_ENDPOINT_REGEX = re.compile(r'.*\.amazonaws\.com(|\.cn)$', re.IGNORECASE)
_AWS_S3_ENDPOINT_REGEX = re.compile(
    _AWS_S3_PREFIX +
    r'((?!s3)(?!-)(?!_)[a-z_\d-]{1,63}(?<!-)(?<!_)\.)*'
    r'amazonaws\.com(|\.cn)$',
    re.IGNORECASE,
)
_AWS_ELB_ENDPOINT_REGEX = re.compile(
    r'^(?!-)(?!_)[a-z_\d-]{1,63}(?<!-)(?<!_)\.'
    r'(?!-)(?!_)[a-z_\d-]{1,63}(?<!-)(?<!_)\.'
    r'elb\.amazonaws\.com$',
    re.IGNORECASE,
)
_AWS_S3_PREFIX_REGEX = re.compile(_AWS_S3_PREFIX, re.IGNORECASE)
REGION_REGEX = re.compile(
    r'^((?!_)(?!-)[a-z_\d-]{1,63}(?<!-)(?<!_))$',
    re.IGNORECASE,
)


def get_user_agent(app_name: str, app_version: str, default=False) -> str:
    """Get user agent header value for app name and version."""
    if default:
        return _DEFAULT_USER_AGENT
    if not (app_name and app_version):
        raise ValueError("Application name and version must be provided.")
    return f"{_DEFAULT_USER_AGENT} {app_name}/{app_version}"


class RegionMap:
    """Thread-safe region map."""

    def __init__(self):
        self._lock = Lock()
        self._map = {}

    def get(self, bucket_name: str) -> Optional[str]:
        """Get region associated to the bucket."""
        with self._lock:
            return self._map.get(bucket_name)

    def set(self, bucket_name: str, region: str):
        """Set region for the bucket."""
        with self._lock:
            self._map[bucket_name] = region

    def remove(self, bucket_name: str):
        """Remove region for the bucket."""
        with self._lock:
            self._map.pop(bucket_name, None)


def headers_to_strings(
        headers: Mapping[str, str | list[str] | tuple[str]],
        titled_key: bool = False,
) -> str:
    """Convert HTTP headers to multi-line string."""
    values = []
    for key, value in headers.items():
        key = key.title() if titled_key else key
        for item in value if isinstance(value, (list, tuple)) else [value]:
            item = re.sub(
                r"Credential=([^/]+)",
                "Credential=*REDACTED*",
                re.sub(
                    r"Signature=([0-9a-f]+)",
                    "Signature=*REDACTED*",
                    item,
                    flags=re.IGNORECASE,
                ),
            ) if titled_key else item
            values.append(f"{key}: {item}")
    return "\n".join(values)


def check_bucket_name(
        bucket_name: str,
        strict: bool = False,
        s3_check: bool = False,
):
    """Check whether bucket name is valid optional with strict check or not."""

    if strict:
        if not _BUCKET_NAME_REGEX.match(bucket_name):
            raise ValueError(f"invalid bucket name {bucket_name}")
    else:
        if not _OLD_BUCKET_NAME_REGEX.match(bucket_name):
            raise ValueError(f"invalid bucket name {bucket_name}")

    if _IPV4_REGEX.match(bucket_name):
        raise ValueError(
            f"bucket name {bucket_name} must not be formatted as an IP address",
        )

    unallowed_successive_chars = ['..', '.-', '-.']
    if any(x in bucket_name for x in unallowed_successive_chars):
        raise ValueError(
            f"bucket name {bucket_name} contains invalid successive characters",
        )

    if s3_check and (
            bucket_name.startswith("xn--") or
            bucket_name.endswith("-s3alias") or
            bucket_name.endswith("--ol-s3")
    ):
        raise ValueError(
            f"bucket name {bucket_name} must not start with 'xn--' and "
            f"must not end with '--s3alias' or '--ol-s3'"
        )


def _check_non_empty_string(string: str | bytes, kind: str):
    """Check whether given string is not empty."""
    try:
        if not string.strip():
            raise ValueError(f"{kind} must be a non-empty string or bytes")
    except AttributeError as exc:
        raise TypeError(f"{kind} must be a string or bytes") from exc


def check_object_name(object_name: str):
    """Check whether given object name is valid."""
    _check_non_empty_string(object_name, "object name")
    tokens = object_name.split("/")
    if "." in tokens or ".." in tokens:
        raise ValueError(
            "object name with '.' or '..' path segment is not supported",
        )


def check_policy(policy: str | bytes):
    """Check whether given policy is valid."""
    _check_non_empty_string(policy, "policy")


def url_replace(
        *,
        url: urllib.parse.SplitResult,
        scheme: Optional[str] = None,
        netloc: Optional[str] = None,
        path: Optional[str] = None,
        query: Optional[str] = None,
        fragment: Optional[str] = None,
) -> urllib.parse.SplitResult:
    """Return new URL with replaced properties in given URL."""
    return urllib.parse.SplitResult(
        scheme if scheme is not None else url.scheme,
        netloc if netloc is not None else url.netloc,
        path if path is not None else url.path,
        query if query is not None else url.query,
        fragment if fragment is not None else url.fragment,
    )


def normalize_headers(headers: Optional[HTTPHeaderDict]) -> HTTPHeaderDict:
    """Normalize headers by prefixing 'X-Amz-Meta-' for user metadata."""
    allowed_headers = [
        "cache-control",
        "content-encoding",
        "content-type",
        "content-disposition",
        "content-language",
    ]

    headers = HTTPHeaderDict() if headers is None else headers
    normalized_headers = HTTPHeaderDict()
    for key in headers:
        values = headers.get_all(key)
        lower_key = key.lower()
        if not (
                lower_key.startswith(("x-amz-", "x-amz-meta-")) or
                lower_key in allowed_headers
        ):
            key = "X-Amz-Meta-" + key
        for value in values:
            normalized_headers.add(key, value)
    return normalized_headers


def parse_url(endpoint: str) -> urllib.parse.SplitResult:
    """Parse url string."""

    url = urllib.parse.urlsplit(endpoint)
    host = url.hostname

    if not host:
        raise ValueError("hostname in endpoint is missing")

    if url.scheme.lower() not in ["http", "https"]:
        raise ValueError("scheme in endpoint must be http or https")

    url = url_replace(url=url, scheme=url.scheme.lower())

    if url.path and url.path != "/":
        raise ValueError("path in endpoint is not allowed")

    url = url_replace(url=url, path="")

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
        url = url_replace(url=url, netloc=host)

    return url


class BaseURL:
    """Base URL of S3 endpoint."""
    _aws_info: Optional[dict]
    _virtual_style_flag: bool
    _url: urllib.parse.SplitResult
    _region: Optional[str]
    _accelerate_host_flag: bool

    def __init__(self, endpoint: str, region: Optional[str]):
        url = parse_url(endpoint)

        if region and not REGION_REGEX.match(region):
            raise ValueError(f"invalid region {region}")

        hostname = url.hostname or ""
        self._aws_info, region_in_host = self._get_aws_info(
            hostname, url.scheme == "https", region)
        self._virtual_style_flag = (
            self._aws_info is not None or hostname.endswith("aliyuncs.com")
        )
        self._url = url
        self._region = region or region_in_host
        self._accelerate_host_flag = False
        if self._aws_info:
            self._region = self._aws_info["region"]
            self._accelerate_host_flag = (
                self._aws_info["s3_prefix"].endswith("s3-accelerate.")
            )

    @staticmethod
    def _get_aws_info(
            host: str,
            https: bool,
            region: Optional[str],
    ) -> tuple[Optional[dict], Optional[str]]:
        """Extract AWS domain information. """

        if not _HOSTNAME_REGEX.match(host):
            return (None, None)

        if _AWS_ELB_ENDPOINT_REGEX.match(host):
            region_in_host = host.split(
                ".elb.amazonaws.com", 1)[0].split(".")[-1]
            return (None, region or region_in_host)

        if not _AWS_ENDPOINT_REGEX.match(host):
            return (None, None)

        if host.startswith("ec2-"):
            return (None, None)

        if not _AWS_S3_ENDPOINT_REGEX.match(host):
            raise ValueError(f"invalid Amazon AWS host {host}")

        matcher = _AWS_S3_PREFIX_REGEX.match(host)
        end = matcher.end() if matcher else 0
        aws_s3_prefix = host[:end]

        if "s3-accesspoint" in aws_s3_prefix and not https:
            raise ValueError(f"use HTTPS scheme for host {host}")

        tokens = host[end:].split(".")
        dualstack = tokens[0] == "dualstack"
        if dualstack:
            tokens = tokens[1:]
        region_in_host = ""
        if tokens[0] not in ["vpce", "amazonaws"]:
            region_in_host = tokens[0]
            tokens = tokens[1:]
        aws_domain_suffix = ".".join(tokens)

        if host in "s3-external-1.amazonaws.com":
            region_in_host = "us-east-1"

        if host in ["s3-us-gov-west-1.amazonaws.com",
                    "s3-fips-us-gov-west-1.amazonaws.com"]:
            region_in_host = "us-gov-west-1"

        if (aws_domain_suffix.endswith(".cn") and
            not aws_s3_prefix.endswith("s3-accelerate.") and
            not region_in_host and
                not region):
            raise ValueError(
                f"region missing in Amazon S3 China endpoint {host}",
            )

        return ({"s3_prefix": aws_s3_prefix,
                 "domain_suffix": aws_domain_suffix,
                 "region": region or region_in_host or None,
                 "dualstack": dualstack}, None)

    @property
    def region(self) -> Optional[str]:
        """Get region."""
        return self._region

    @property
    def is_https(self) -> bool:
        """Check if scheme is HTTPS."""
        return self._url.scheme == "https"

    @property
    def host(self) -> str:
        """Get hostname."""
        return self._url.netloc

    @property
    def is_aws_host(self) -> bool:
        """Check if URL points to AWS host."""
        return self._aws_info is not None

    @property
    def aws_s3_prefix(self) -> Optional[str]:
        """Get AWS S3 domain prefix."""
        return self._aws_info["s3_prefix"] if self._aws_info else None

    @aws_s3_prefix.setter
    def aws_s3_prefix(self, s3_prefix: str):
        """Set AWS s3 domain prefix."""
        if not _AWS_S3_PREFIX_REGEX.match(s3_prefix):
            raise ValueError(f"invalid AWS S3 domain prefix {s3_prefix}")
        if self._aws_info:
            self._aws_info["s3_prefix"] = s3_prefix

    @property
    def accelerate_host_flag(self) -> bool:
        """Get AWS accelerate host flag."""
        return self._accelerate_host_flag

    @accelerate_host_flag.setter
    def accelerate_host_flag(self, flag: bool):
        """Set AWS accelerate host flag."""
        self._accelerate_host_flag = flag

    @property
    def dualstack_host_flag(self) -> bool:
        """Check if URL points to AWS dualstack host."""
        return self._aws_info["dualstack"] if self._aws_info else False

    @dualstack_host_flag.setter
    def dualstack_host_flag(self, flag: bool):
        """Set AWS dualstack host."""
        if self._aws_info:
            self._aws_info["dualstack"] = flag

    @property
    def virtual_style_flag(self) -> bool:
        """Check to use virtual style or not."""
        return self._virtual_style_flag

    @virtual_style_flag.setter
    def virtual_style_flag(self, flag: bool):
        """Check to use virtual style or not."""
        self._virtual_style_flag = flag

    @classmethod
    def _build_aws_url(
            cls,
            *,
            aws_info: dict,
            url: urllib.parse.SplitResult,
            bucket_name: Optional[str],
            enforce_path_style: bool,
            region: str,
    ) -> urllib.parse.SplitResult:
        """Build URL for given information."""
        s3_prefix = aws_info["s3_prefix"]
        domain_suffix = aws_info["domain_suffix"]

        host = f"{s3_prefix}{domain_suffix}"
        if host in ["s3-external-1.amazonaws.com",
                    "s3-us-gov-west-1.amazonaws.com",
                    "s3-fips-us-gov-west-1.amazonaws.com"]:
            return url_replace(url=url, netloc=host)

        netloc = s3_prefix
        if "s3-accelerate" in s3_prefix:
            if "." in (bucket_name or ""):
                raise ValueError(
                    f"bucket name '{bucket_name}' with '.' is not allowed "
                    f"for accelerate endpoint"
                )
            if enforce_path_style:
                netloc = netloc.replace("-accelerate", "", 1)

        if aws_info["dualstack"]:
            netloc += "dualstack."
        if "s3-accelerate" not in s3_prefix:
            netloc += region + "."
        netloc += domain_suffix

        return url_replace(url=url, netloc=netloc)

    def _build_list_buckets_url(
            self,
            url: urllib.parse.SplitResult,
            region: Optional[str],
    ) -> urllib.parse.SplitResult:
        """Build URL for ListBuckets API."""
        if not self._aws_info:
            return url

        s3_prefix = self._aws_info["s3_prefix"]
        domain_suffix = self._aws_info["domain_suffix"]

        host = f"{s3_prefix}{domain_suffix}"
        if host in ["s3-external-1.amazonaws.com",
                    "s3-us-gov-west-1.amazonaws.com",
                    "s3-fips-us-gov-west-1.amazonaws.com"]:
            return url_replace(url=url, netloc=host)

        if s3_prefix.startswith("s3.") or s3_prefix.startswith("s3-"):
            s3_prefix = "s3."
            cn_suffix = ".cn" if domain_suffix.endswith(".cn") else ""
            domain_suffix = f"amazonaws.com{cn_suffix}"
        return url_replace(
            url=url,
            netloc=f"{s3_prefix}{region}.{domain_suffix}",
        )

    def build(
            self,
            *,
            method: str,
            region: str,
            bucket_name: Optional[str] = None,
            object_name: Optional[str] = None,
            query_params: Optional[HTTPQueryDict] = None,
            extra_query_params: Optional[HTTPQueryDict] = None,
    ) -> urllib.parse.SplitResult:
        """Build URL for given information."""
        if not bucket_name and object_name:
            raise ValueError(
                f"empty bucket name for object name {object_name}",
            )

        url = url_replace(url=self._url, path="/")

        query_params = HTTPQueryDict().extend(query_params).extend(
            extra_query_params,
        )
        url = url_replace(url=url, query=f"{query_params}")

        if not bucket_name:
            return self._build_list_buckets_url(url, region)

        enforce_path_style = (
            # CreateBucket API requires path style in Amazon AWS S3.
            (method == "PUT" and not object_name and not query_params) or

            # GetBucketLocation API requires path style in Amazon AWS S3.
            (query_params and "location" in query_params) or

            # Use path style for bucket name containing '.' which causes
            # SSL certificate validation error.
            ("." in bucket_name and self._url.scheme == "https")
        )

        if self._aws_info:
            url = BaseURL._build_aws_url(
                aws_info=self._aws_info,
                url=url,
                bucket_name=bucket_name,
                enforce_path_style=enforce_path_style,
                region=region,
            )

        netloc = url.netloc
        path = "/"

        if enforce_path_style or not self._virtual_style_flag:
            path = f"/{bucket_name}"
        else:
            netloc = f"{bucket_name}.{netloc}"
        if object_name:
            path += ("" if path.endswith("/") else "/") + quote(object_name)

        return url_replace(url=url, netloc=netloc, path=path)


class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """

    def __init__(
            self,
            tasks_queue: Queue,
            results_queue: Queue,
            exceptions_queue: Queue,
    ):
        Thread.__init__(self, daemon=True)
        self._tasks_queue = tasks_queue
        self._results_queue = results_queue
        self._exceptions_queue = exceptions_queue
        self.start()

    def run(self):
        """ Continuously receive tasks and execute them """
        while True:
            task = self._tasks_queue.get()
            if not task:
                self._tasks_queue.task_done()
                break
            func, args, kargs, cleanup_func = task
            # No exception detected in any thread,
            # continue the execution.
            if self._exceptions_queue.empty():
                try:
                    result = func(*args, **kargs)
                    self._results_queue.put(result)
                except Exception as ex:  # pylint: disable=broad-except
                    self._exceptions_queue.put(ex)

            # call cleanup i.e. Semaphore.release irrespective of task
            # execution to avoid race condition.
            cleanup_func()
            # Mark this task as done, whether an exception happened or not
            self._tasks_queue.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """
    _results_queue: Queue
    _exceptions_queue: Queue
    _tasks_queue: Queue
    _sem: BoundedSemaphore
    _num_threads: int

    def __init__(self, num_threads: int):
        self._results_queue = Queue()
        self._exceptions_queue = Queue()
        self._tasks_queue = Queue()
        self._sem = BoundedSemaphore(num_threads)
        self._num_threads = num_threads

    def add_task(self, func, *args, **kargs):
        """
        Add a task to the queue. Calling this function can block
        until workers have a room for processing new tasks. Blocking
        the caller also prevents the latter from allocating a lot of
        memory while workers are still busy running their assigned tasks.
        """
        self._sem.acquire()  # pylint: disable=consider-using-with
        cleanup_func = self._sem.release
        self._tasks_queue.put((func, args, kargs, cleanup_func))

    def start_parallel(self):
        """ Prepare threads to run tasks"""
        for _ in range(self._num_threads):
            Worker(
                self._tasks_queue, self._results_queue, self._exceptions_queue,
            )

    def result(self) -> Queue:
        """ Stop threads and return the result of all called tasks """
        # Send None to all threads to cleanly stop them
        for _ in range(self._num_threads):
            self._tasks_queue.put(None)
        # Wait for completion of all the tasks in the queue
        self._tasks_queue.join()
        # Check if one of the thread raised an exception, if yes
        # raise it here in the function
        if not self._exceptions_queue.empty():
            raise self._exceptions_queue.get()
        return self._results_queue
