# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2020 MinIO, Inc.
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

"""Credential providers."""

import configparser
import json
import os
import sys
from datetime import datetime, timedelta

import urllib3
from urllib3.exceptions import HTTPError, ResponseError

from .credentials import Provider, Value

RFC3339NANO = "%Y-%m-%dT%H:%M:%S.%fZ"
RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


class AssumeRoleProvider(Provider):
    """Assume-role credential provider."""

    def __init__(self, provider_func):
        self._provider_func = provider_func
        self._value = None
        self._expiry = None

    def retrieve(self):
        """Retrieve credential value and its expiry from provider callback."""
        if (
                not self._value or
                (self._expiry and self._expiry < datetime.utcnow())
        ):
            self._value, self._expiry = self._provider_func()
        return self._value, self._expiry


class Chain(Provider):
    """Chained credential provider."""

    def __init__(self, providers):
        self._providers = providers
        self._provider = None

    def retrieve(self):
        """
        Retrieve credential value and its expiry from one of available
        provider.
        """
        value_error = ValueError("no credentials retrieved")
        try:
            if self._provider:
                return self._provider.retrieve()
        except ValueError as exc:
            value_error = exc

        for provider in self._providers:
            try:
                creds, expiry = provider.retrieve()
                if creds:
                    self._provider = provider
                    return creds, expiry
            except ValueError as exc:
                value_error = exc

        raise value_error


class EnvAWS(Provider):
    """Credential provider from AWS environment variables."""

    def __init__(self):
        access_key = (
            os.environ.get("AWS_ACCESS_KEY_ID") or
            os.environ.get("AWS_ACCESS_KEY")
        )
        secret_key = (
            os.environ.get("AWS_SECRET_ACCESS_KEY") or
            os.environ.get("AWS_SECRET_KEY")
        )
        session_token = os.environ.get("AWS_SESSION_TOKEN")
        self._value = Value(
            access_key,
            secret_key,
            session_token=session_token,
        )

    def retrieve(self):
        """Retrieve credential value."""
        return self._value, None


class EnvMinio(Provider):
    """Credential provider from MinIO environment variables."""

    def __init__(self):
        self._value = Value(
            os.environ.get("MINIO_ACCESS_KEY"),
            os.environ.get("MINIO_SECRET_KEY"),
        )

    def retrieve(self):
        """Retrieve credential value."""
        return self._value, None


class FileAWSCredentials(Provider):
    """Credential provider from AWS credential file."""

    def __init__(self, filename=None, profile=None):
        self._filename = (
            filename or
            os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or
            os.path.join(os.environ.get("HOME"), ".aws", "credentials")
        )
        self._profile = profile or os.environ.get("AWS_PROFILE") or "default"

    def retrieve(self):
        """Retrieve credential value from AWS configuration file."""
        parser = configparser.ConfigParser()
        parser.read(self._filename)
        access_key = parser.get(
            self._profile,
            "aws_access_key_id",
            fallback=None,
        )
        secret_key = parser.get(
            self._profile,
            "aws_secret_access_key",
            fallback=None,
        )
        session_token = parser.get(
            self._profile,
            "aws_session_token",
            fallback=None,
        )
        return Value(
            access_key,
            secret_key,
            session_token=session_token,
        ), None


class FileMinioClient(Provider):
    """Credential provider from MinIO Client configuration file."""

    def __init__(self, filename=None, alias=None):
        self._filename = (
            filename or
            os.path.join(
                os.environ.get("HOME"),
                "mc" if sys.platform == "win32" else ".mc",
                "config.json",
            )
        )
        self._alias = alias or os.environ.get("MINIO_ALIAS") or "s3"

    def retrieve(self):
        """Retrieve credential value from MinIO client configuration file."""
        try:
            with open(self._filename) as conf_file:
                config = json.load(conf_file)
                creds = config.get("hosts", {}).get(self._alias, {})
        except (OSError, ValueError):
            creds = {}

        return Value(
            creds.get("accessKey"),
            creds.get("secretKey"),
        ), None


class IAMProvider(Provider):
    """
        IAM EC2/ECS credential provider.

        expiry_delta param is used to create a window to the token
        expiration time. If expiry_delta is greater than 0 the
        expiration time will be reduced by the delta value.

        Using a delta value is helpful to trigger credentials to
        expire sooner than the expiration time given to ensure no
        requests are made with expired token.

    """

    def __init__(self,
                 endpoint=None,
                 http_client=None,
                 expiry_delta=None,
                 is_ecs_task=False):

        default_iam_role_endpoint = "http://169.254.169.254"
        default_ecs_role_endpoint = "http://169.254.170.2"

        self._is_ecs_task = is_ecs_task

        if self._is_ecs_task:
            default_endpoint = default_ecs_role_endpoint
        else:
            default_endpoint = default_iam_role_endpoint

        self._endpoint = endpoint or default_endpoint
        self._http_client = http_client or urllib3.PoolManager(
            retries=urllib3.Retry(
                total=5,
                backoff_factor=0.2,
                status_forcelist=[500, 502, 503, 504],
            ),
        )
        if expiry_delta is None:
            self._expiry_delta = timedelta(seconds=10)
        else:
            self._expiry_delta = expiry_delta

    def retrieve(self):
        """
            Retrieve credential value and its expiry from IAM EC2 instance role
            or ECS task role.
        """
        if not self._is_ecs_task:
            # Get role names and get the first role for EC2.
            creds_path = "/latest/meta-data/iam/security-credentials"
            url = self._endpoint + creds_path
            res = self._http_client.urlopen("GET", url)
            if res.status != 200:
                raise HTTPError(
                    "request failed with status {0}".format(res.status),
                )
            role_names = res.data.decode("utf-8").split("\n")
            if not role_names:
                raise ResponseError("no role names found in response")
            credentials_url = self._endpoint + creds_path + "/" + role_names[0]
        else:
            # This URL directly gives the credentials for an ECS task
            relative_url_var = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
            creds_path = os.environ.get(relative_url_var) or ""
            credentials_url = self._endpoint + creds_path

        # Get credentials of role.
        res = self._http_client.urlopen("GET", credentials_url)
        if res.status != 200:
            raise HTTPError(
                "request failed with status {0}".format(res.status),
            )
        data = json.loads(res.data)

        # Note the response in ECS does not include the "Code" key.
        if not self._is_ecs_task and data["Code"] != "Success":
            raise ResponseError(
                "credential retrieval failed with code {0}".format(
                    data["Code"]),
            )

        try:
            expiration = datetime.strptime(data["Expiration"], RFC3339NANO)
        except ValueError:
            expiration = datetime.strptime(data["Expiration"], RFC3339)
        return Value(
            data["AccessKeyId"],
            data["SecretAccessKey"],
            session_token=data["Token"],
        ), expiration - self._expiry_delta


class Static(Provider):
    """Fixed credential provider."""

    def __init__(self, access_key, secret_key, session_token=None,
                 expiry=None):
        self._value = Value(access_key, secret_key, session_token)
        self._expiry = expiry

    def retrieve(self):
        """Retrieve credential value and its expiry."""
        return self._value, self._expiry
