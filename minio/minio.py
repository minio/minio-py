# Minimal Object Storage Library, (C) 2015 Minio, Inc.
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

import collections
import hashlib
import platform
from urlparse import urlparse

import requests

from .exceptions import BucketExistsException, InvalidBucketNameException, BucketNotFoundException
from .parsers import parse_list_buckets, parse_acl
from .region import get_region
from .signer import sign_v4
from .xml_requests import bucket_constraint

__author__ = 'minio'


class Minio:
    def __init__(self, url, access_key=None, secret_key=None):
        if not isinstance(url, basestring):
            raise TypeError(url)
        url_components = urlparse(url)

        if url_components.scheme is '':
            raise ValueError('url')

        if url_components.netloc is '':
            raise ValueError('url')

        self._scheme = url_components.scheme
        self._location = url_components.netloc
        self._access_key = access_key
        self._secret_key = secret_key
        self._user_agent = 'minio-py/' + '0.0.1' + ' (' + platform.system() + '; ' + platform.machine() + ')'

    # Client level
    def add_user_agent(self, name, version, parameters):
        if not isinstance(name, basestring):
            raise TypeError('name')
        name = name.strip()
        if name == '':
            raise ValueError('name')

        if not isinstance(version, basestring):
            raise TypeError('version')
        version = version.strip()
        if version == '':
            raise ValueError('version')

        for parameter in parameters:
            if parameter == '':
                raise ValueError('parameters')

        joined_parameters = '; '.join(parameters)
        components = [' ', name, '/', version, ' (', joined_parameters, ')']
        self._user_agent += ''.join(components)

    # Bucket level
    # noinspection PyUnusedLocal
    def make_bucket(self, bucket, acl=None):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'PUT'
        url = self._get_target_url(bucket)
        headers = {}

        region = get_region(self._location)

        content = ''
        if region is not 'us-east-1':
            content = bucket_constraint(region)
            headers['Content-Length'] = str(len(content))

        content_sha256 = get_sha256(content)

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key, content_hash=content_sha256)

        response = requests.put(url, data=content, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def list_buckets(self, prefix=None, recursive=True):
        if prefix is not None:
            if not isinstance(prefix, basestring):
                raise TypeError

        if recursive is not None:
            if not isinstance(recursive, bool):
                raise TypeError

        url = self._get_target_url()
        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)

        return parse_list_buckets(response.content)

    def bucket_exists(self, bucket):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'HEAD'
        url = self._get_target_url(bucket)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.head(url, headers=headers)

        if response.status_code == 200:
            return True

        parse_error(response)

    def remove_bucket(self, bucket):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'DELETE'
        url = self._get_target_url(bucket)
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.delete(url, headers=headers)

        if response.status_code != 200:
            parse_error(response)

    def get_bucket_acl(self, bucket):
        if not isinstance(bucket, basestring):
            raise TypeError('bucket')
        bucket = bucket.strip()
        if bucket == '':
            raise ValueError

        method = 'GET'
        url = self._get_target_url(bucket, query={"acl": None})
        headers = {}

        headers = sign_v4(method=method, url=url, headers=headers, access_key=self._access_key,
                          secret_key=self._secret_key)

        response = requests.get(url, headers=headers)

        return parse_acl(response.content)

    def set_bucket_acl(self, bucket, acl):
        pass

    def drop_all_incomplete_uploads(self, bucket):
        pass

    # Object Level
    def get_key(self, bucket, key):
        pass

    def put_key(self, bucket, key, content_type, length, data):
        pass

    def list_keys(self, bucket, prefix, recursive):
        pass

    def stat_key(self, bucket, key):
        pass

    def remove_key(self, bucket, key):
        pass

    def drop_incomplete_upload(self, bucket, key):
        pass

    # helper functions
    def _get_target_url(self, bucket=None, key=None, query=None):
        url_components = [self._scheme, '://', self._location, '/']

        if bucket is not None:
            url_components.append(bucket)
            if key is not None:
                url_components.append('/')
                url_components.append(key)

        if query is not None:
            ordered_query = collections.OrderedDict(sorted(query.items()))
            query_components = []
            for component_key in ordered_query:
                single_component = [component_key]
                if ordered_query[component_key] is not None:
                    single_component.append('=')
                    single_component.append(ordered_query[component_key])
                query_components.append(''.join(single_component))

            query_string = '&'.join(query_components)
            if query_string is not '':
                url_components.append('?')
                url_components.append(query_string)

        return ''.join(url_components)


def parse_error(response):
    if response.status_code == 404:
        raise BucketNotFoundException()
    if response.status_code == 400:
        raise InvalidBucketNameException()
    if response.status_code == 409:
        raise BucketExistsException()
    raise NotImplementedError()


def get_sha256(content):
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.digest()
