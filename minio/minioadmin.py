# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2021 MinIO, Inc.
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

# pylint: disable=too-many-public-methods

"""MinIO Admin Client to perform MinIO administration operations."""

from __future__ import absolute_import

import json
import os
from datetime import timedelta
from enum import Enum
from urllib.parse import urlunsplit

import certifi
import urllib3
from urllib3._collections import HTTPHeaderDict

from minio.crypto import decrypt, encrypt

from . import time
from .credentials.providers import Provider
from .error import MinioAdminException
from .helpers import (_DEFAULT_USER_AGENT, _REGION_REGEX, _parse_url,
                      headers_to_strings, queryencode, sha256_hash,
                      url_replace)
from .signer import sign_v4_s3

_COMMAND = Enum(
    "Command",
    {
        "ADD_USER": "add-user",
        "USER_INFO": "user-info",
        "LIST_USERS": "list-users",
        "REMOVE_USER": "remove-user",
        "SET_USER_STATUS": "set-user-status",
        "ADD_CANNED_POLICY": "add-canned-policy",
        "SET_USER_OR_GROUP_POLICY": "set-user-or-group-policy",
        "LIST_CANNED_POLICIES": "list-canned-policies",
        "REMOVE_CANNED_POLICY": "remove-canned-policy",
        "UNSET_USER_OR_GROUP_POLICY": "idp/builtin/policy/detach",
        "CANNED_POLICY_INFO": "info-canned-policy",
        "SET_BUCKET_QUOTA": "set-bucket-quota",
        "GET_BUCKET_QUOTA": "get-bucket-quota",
        "DATA_USAGE_INFO": "datausageinfo",
        "ADD_UPDATE_REMOVE_GROUP": "update-group-members",
        "SET_GROUP_STATUS": "set-group-status",
        "GROUP_INFO": "group",
        "LIST_GROUPS": "groups",
        "INFO": "info",
        "SERVICE": "service",
        "UPDATE": "update",
        "TOP_LOCKS": "top/locks",
        "HELP_CONFIG": "help-config-kv",
        "GET_CONFIG": "get-config-kv",
        "SET_CONFIG": "set-config-kv",
        "DELETE_CONFIG": "del-config-kv",
        "LIST_CONFIG_HISTORY": "list-config-history-kv",
        "RESOTRE_CONFIG_HISTORY": "restore-config-history-kv",
        "START_PROFILE": "profile",
        "CREATE_KMS_KEY": "kms/key/create",
        "GET_KMS_KEY_STATUS": "kms/key/status",
        "SITE_REPLICATION_ADD": "site-replication/add",
        "SITE_REPLICATION_INFO": "site-replication/info",
        "SITE_REPLICATION_STATUS": "site-replication/status",
        "SITE_REPLICATION_EDIT": "site-replication/edit",
        "SITE_REPLICATION_REMOVE": "site-replication/remove",
    },
)


class MinioAdmin:
    """Client to perform MinIO administration operations."""

    def __init__(self, endpoint,
                 credentials,
                 region="",
                 secure=True,
                 cert_check=True,
                 http_client=None):
        url = _parse_url(("https://" if secure else "http://") + endpoint)
        if not isinstance(credentials, Provider):
            raise ValueError("valid credentials must be provided")
        if region and not _REGION_REGEX.match(region):
            raise ValueError(f"invalid region {region}")
        if http_client:
            if not isinstance(http_client, urllib3.poolmanager.PoolManager):
                raise ValueError(
                    "HTTP client should be instance of "
                    "`urllib3.poolmanager.PoolManager`"
                )
        else:
            timeout = timedelta(minutes=5).seconds
            http_client = urllib3.PoolManager(
                timeout=urllib3.util.Timeout(connect=timeout, read=timeout),
                maxsize=10,
                cert_reqs='CERT_REQUIRED' if cert_check else 'CERT_NONE',
                ca_certs=os.environ.get('SSL_CERT_FILE') or certifi.where(),
                retries=urllib3.Retry(
                    total=5,
                    backoff_factor=0.2,
                    status_forcelist=[500, 502, 503, 504]
                )
            )

        self._url = url
        self._provider = credentials
        self._region = region
        self._secure = secure
        self._cert_check = cert_check
        self._http = http_client
        self._user_agent = _DEFAULT_USER_AGENT
        self._trace_stream = None

    def __del__(self):
        self._http.clear()

    def _url_open(self, method, command, query_params=None, body=None):
        """Execute HTTP request."""
        creds = self._provider.retrieve()

        url = url_replace(self._url, path="/minio/admin/v3/"+command.value)
        query = []
        for key, values in sorted((query_params or {}).items()):
            values = values if isinstance(values, (list, tuple)) else [values]
            query += [
                f"{queryencode(key)}={queryencode(value)}"
                for value in sorted(values)
            ]
        url = url_replace(url, query="&".join(query))

        date = time.utcnow()
        headers = {
            "Host": url.netloc,
            "User-Agent": self._user_agent,
            "x-amz-date": time.to_amz_date(date),
            "x-amz-content-sha256": sha256_hash(body),
            "Content-Type": "application/octet-stream"
        }
        if creds.session_token:
            headers["X-Amz-Security-Token"] = creds.session_token
        if body:
            headers["Content-Length"] = str(len(body))

        headers = sign_v4_s3(
            method,
            url,
            self._region,
            headers,
            creds,
            headers.get("x-amz-content-sha256"),
            date,
        )

        if self._trace_stream:
            self._trace_stream.write("---------START-HTTP---------\n")
            query = ("?" + url.query) if url.query else ""
            self._trace_stream.write(f"{method} {url.path}{query} HTTP/1.1\n")
            self._trace_stream.write(
                headers_to_strings(headers, titled_key=True),
            )
            self._trace_stream.write("\n")
            if body is not None:
                self._trace_stream.write("\n")
                self._trace_stream.write(
                    body.decode() if isinstance(body, bytes) else str(body),
                )
                self._trace_stream.write("\n")
            self._trace_stream.write("\n")

        http_headers = HTTPHeaderDict()
        for key, value in headers.items():
            if isinstance(value, (list, tuple)):
                _ = [http_headers.add(key, val) for val in value]
            else:
                http_headers.add(key, value)

        response = self._http.urlopen(
            method,
            urlunsplit(url),
            body=body,
            headers=http_headers,
            preload_content=True,
        )

        if self._trace_stream:
            self._trace_stream.write(f"HTTP/1.1 {response.status}\n")
            self._trace_stream.write(
                headers_to_strings(response.headers),
            )
            self._trace_stream.write("\n")
            self._trace_stream.write("\n")
            self._trace_stream.write(response.data.decode())
            self._trace_stream.write("\n")
            self._trace_stream.write("----------END-HTTP----------\n")

        if response.status in [200, 204, 206]:
            return response

        raise MinioAdminException(response.status, response.data.decode())

    def set_app_info(self, app_name, app_version):
        """
        Set your application name and version to user agent header.

        :param app_name: Application name.
        :param app_version: Application version.

        Example::
            client.set_app_info('my_app', '1.0.2')
        """
        if not (app_name and app_version):
            raise ValueError("Application name/version cannot be empty.")
        self._user_agent = f"{_DEFAULT_USER_AGENT} {app_name}/{app_version}"

    def trace_on(self, stream):
        """
        Enable http trace.

        :param stream: Stream for writing HTTP call tracing.
        """
        if not stream:
            raise ValueError('Input stream for trace output is invalid.')
        # Save new output stream.
        self._trace_stream = stream

    def trace_off(self):
        """
        Disable HTTP trace.
        """
        self._trace_stream = None

    def service_restart(self):
        """Restart MinIO service."""
        response = self._url_open(
            "POST",
            _COMMAND.SERVICE,
            query_params={"action": "restart"}
        )
        return response.data.decode()

    def service_stop(self):
        """Stop MinIO service."""
        response = self._url_open(
            "POST",
            _COMMAND.SERVICE,
            query_params={"action": "stop"}
        )
        return response.data.decode()

    def update(self):
        """Update MinIO."""
        response = self._url_open(
            "POST",
            _COMMAND.UPDATE,
            query_params={"updateURL": ""}
        )
        return response.data.decode()

    def info(self):
        """Get MinIO server information."""
        response = self._url_open(
            "GET",
            _COMMAND.INFO,
        )
        return response.data.decode()

    def user_add(self, access_key, secret_key):
        """Create user with access and secret keys"""
        body = json.dumps(
            {"status": "enabled", "secretKey": secret_key}).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.ADD_USER,
            query_params={"accessKey": access_key},
            body=encrypt(body, self._provider.retrieve().secret_key),
        )
        return response.data.decode()

    def user_disable(self, access_key):
        """Disable user."""
        response = self._url_open(
            "PUT",
            _COMMAND.SET_USER_STATUS,
            query_params={"accessKey": access_key, "status": "disabled"}
        )
        return response.data.decode()

    def user_enable(self, access_key):
        """Enable user."""
        response = self._url_open(
            "PUT",
            _COMMAND.SET_USER_STATUS,
            query_params={"accessKey": access_key, "status": "enabled"}
        )
        return response.data.decode()

    def user_remove(self, access_key):
        """Delete user"""
        response = self._url_open(
            "DELETE",
            _COMMAND.REMOVE_USER,
            query_params={"accessKey": access_key},
        )
        return response.data.decode()

    def user_info(self, access_key):
        """Get information about user"""
        response = self._url_open(
            "GET",
            _COMMAND.USER_INFO,
            query_params={"accessKey": access_key},
        )
        return response.data.decode()

    def user_list(self):
        """List all users"""
        response = self._url_open("GET", _COMMAND.LIST_USERS)
        plain_data = decrypt(
            response.data, self._provider.retrieve().secret_key
        )
        return plain_data.decode()

    def group_add(self, group_name, members):
        """Add users a new or existing group."""
        body = json.dumps({
            "group": group_name,
            "members": members,
            "isRemove": False
        }).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.ADD_UPDATE_REMOVE_GROUP,
            body=body,
        )
        return response.data.decode()

    def group_disable(self, group_name):
        """Disable group."""
        response = self._url_open(
            "PUT",
            _COMMAND.SET_GROUP_STATUS,
            query_params={"group": group_name, "status": "disabled"}
        )
        return response.data.decode()

    def group_enable(self, group_name):
        """Enable group."""
        response = self._url_open(
            "PUT",
            _COMMAND.SET_GROUP_STATUS,
            query_params={"group": group_name, "status": "enabled"}
        )
        return response.data.decode()

    def group_remove(self, group_name, members=None):
        """Remove group or members from a group."""
        body = json.dumps({
            "group": group_name,
            "members": members,
            "isRemove": True
        }).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.ADD_UPDATE_REMOVE_GROUP,
            body=body,
        )
        return response.data.decode()

    def group_info(self, group_name):
        """Get group information."""
        response = self._url_open(
            "GET",
            _COMMAND.GROUP_INFO,
            query_params={"group": group_name},
        )
        return response.data.decode()

    def group_list(self):
        """List groups."""
        response = self._url_open("GET", _COMMAND.LIST_GROUPS)
        return response.data.decode()

    def policy_add(self, policy_name, policy_file):
        """Add new policy."""
        with open(policy_file, encoding='utf-8') as file:
            response = self._url_open(
                "PUT",
                _COMMAND.ADD_CANNED_POLICY,
                query_params={"name": policy_name},
                body=file.read().encode(),
            )
            return response.data.decode()

    def policy_remove(self, policy_name):
        """Remove policy."""
        response = self._url_open(
            "DELETE",
            _COMMAND.REMOVE_CANNED_POLICY,
            query_params={"name": policy_name},
        )
        return response.data.decode()

    def policy_info(self, policy_name):
        """Get policy information."""
        response = self._url_open(
            "GET",
            _COMMAND.CANNED_POLICY_INFO,
            query_params={"name": policy_name},
        )
        return response.data.decode()

    def policy_list(self):
        """List policies."""
        response = self._url_open("GET", _COMMAND.LIST_CANNED_POLICIES)
        return response.data.decode()

    def policy_set(self, policy_name, user=None, group=None):
        """Set IAM policy on a user or group."""
        if (user is not None) ^ (group is not None):
            response = self._url_open(
                "PUT",
                _COMMAND.SET_USER_OR_GROUP_POLICY,
                query_params={"userOrGroup": user or group,
                              "isGroup": "true" if group else "false",
                              "policyName": policy_name},
            )
            return response.data.decode()
        raise ValueError("either user or group must be set")

    def policy_unset(self, policy_name, user=None, group=None):
        """Unset an IAM policy for a user or group."""
        body = json.dumps({
            "policies": [policy_name],
            "group": group,
            "user": user
        }).encode()
        if (user is not None) ^ (group is not None):
            response = self._url_open(
                "POST",
                _COMMAND.UNSET_USER_OR_GROUP_POLICY,
                body=encrypt(body, self._provider.retrieve().secret_key),
            )
            plain_data = decrypt(
                response.data, self._provider.retrieve().secret_key
            )
            return plain_data.decode()
        raise ValueError("either user or group must be set")

    def config_get(self, key=None):
        """Get configuration parameters."""
        if not key:
            response = self._url_open(
                "GET",
                _COMMAND.HELP_CONFIG,
                query_params={"key": "", "subSys": ""},
            )
            return response.data.decode()

        response = self._url_open(
            "GET",
            _COMMAND.GET_CONFIG,
            query_params={"key": key, "subSys": ""},
        )
        plain_text = decrypt(
            response.data, self._provider.retrieve().secret_key
        )
        return plain_text.decode()

    def config_set(self, key=None, config=None):
        """Set configuration parameters."""
        body = " ".join(
            [key] + [f"{name}={value}" for name, value in config.items()]
        ).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.SET_CONFIG,
            body=encrypt(body, self._provider.retrieve().secret_key),
        )
        return response.data.decode()

    def config_reset(self, key, name=None):
        """Reset configuration parameters."""
        if name:
            key += ":" + name
        body = key.encode()
        response = self._url_open(
            "DELETE",
            _COMMAND.DELETE_CONFIG,
            body=encrypt(body, self._provider.retrieve().secret_key),
        )
        return response.data.decode()

    def config_history(self):
        """Get historic configuration changes."""
        response = self._url_open(
            "GET",
            _COMMAND.LIST_CONFIG_HISTORY,
            query_params={"count": "10"}
        )
        plain_text = decrypt(
            response.data, self._provider.retrieve().secret_key
        )
        return plain_text.decode()

    def config_restore(self, restore_id):
        """Restore to a specific configuration history."""
        response = self._url_open(
            "PUT",
            _COMMAND.RESOTRE_CONFIG_HISTORY,
            query_params={"restoreId": restore_id}
        )
        return response.data.decode()

    def profile_start(self, profilers=()):
        """Runs a system profile"""
        response = self._url_open(
            "POST",
            _COMMAND.START_PROFILE,
            query_params={"profilerType;": ",".join(profilers)},
        )
        return response.data

    def top_locks(self):
        """Get a list of the 10 oldest locks on a MinIO cluster."""
        response = self._url_open(
            "GET",
            _COMMAND.TOP_LOCKS,
        )
        return response.data.decode()

    def kms_key_create(self, key=None):
        """Create a new KMS master key."""
        response = self._url_open(
            "POST",
            _COMMAND.CREATE_KMS_KEY,
            query_params={"key-id": key},
        )
        return response.data.decode()

    def kms_key_status(self, key=None):
        """Get status information of a KMS master key."""
        response = self._url_open(
            "GET",
            _COMMAND.GET_KMS_KEY_STATUS,
            query_params={"key-id": key or ""}
        )
        return response.data.decode()

    def add_site_replication(self, peer_sites):
        """Add peer sites to site replication."""
        body = json.dumps(
            [peer_site.to_dict() for peer_site in peer_sites]).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.SITE_REPLICATION_ADD,
            query_params={"api-version": "1"},
            body=encrypt(body, self._provider.retrieve().secret_key),
        )
        return response.data.decode()

    def get_site_replication_info(self):
        """Get site replication information."""
        response = self._url_open("GET", _COMMAND.SITE_REPLICATION_INFO)
        return response.data.decode()

    def get_site_replication_status(self, options):
        """Get site replication information."""
        response = self._url_open(
            "GET",
            _COMMAND.SITE_REPLICATION_STATUS,
            query_params=options.to_query_params(),
        )
        return response.data.decode()

    def edit_site_replication(self, peer_info):
        """Edit site replication with given peer information."""
        body = json.dumps(peer_info.to_dict()).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.SITE_REPLICATION_EDIT,
            query_params={"api-version": "1"},
            body=encrypt(body, self._provider.retrieve().secret_key),
        )
        return response.data.decode()

    def remove_site_replication(self, sites=None, all_sites=False):
        """Remove given sites or all sites from site replication."""
        data = {}
        if all_sites:
            data.update({"all": True})
        elif sites:
            data.update({"sites": sites})
        else:
            raise ValueError("either sites or all flag must be given")
        body = json.dumps(data).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.SITE_REPLICATION_REMOVE,
            query_params={"api-version": "1"},
            body=encrypt(body, self._provider.retrieve().secret_key),
        )
        return response.data.decode()

    def bucket_quota_set(self, bucket, size):
        """Set bucket quota configuration."""
        body = json.dumps({"quota": size, "quotatype": "hard"}).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.SET_BUCKET_QUOTA,
            query_params={"bucket": bucket},
            body=body
        )
        return response.data.decode()

    def bucket_quota_clear(self, bucket):
        """Clear bucket quota configuration."""
        body = json.dumps({"quota": 0, "quotatype": "hard"}).encode()
        response = self._url_open(
            "PUT",
            _COMMAND.SET_BUCKET_QUOTA,
            query_params={"bucket": bucket},
            body=body
        )
        return response.data.decode()

    def bucket_quota_get(self, bucket):
        """Get bucket quota configuration."""
        response = self._url_open(
            "GET",
            _COMMAND.GET_BUCKET_QUOTA,
            query_params={"bucket": bucket}
        )
        return response.data.decode()
