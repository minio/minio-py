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
import platform

from urlparse import urlparse
from urllib3 import connectionpool

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
        self._accessKey = access_key
        self._secretKey = secret_key
        self._user_agent = 'minio-py/' + '0.0.1' + ' (' + platform.system() + '; ' + platform.machine() + ')'

    # Client level
    def add_user_agent(self, name, version, parameters):
        if not isinstance(name, basestring):
            raise TypeError('name')
        if name == '':
            raise ValueError('name')

        if not isinstance(version, basestring):
            raise TypeError('version')
        if version == '':
            raise ValueError('version')

        for parameter in parameters:
            if parameter == '':
                raise ValueError('parameters')

        joined_parameters = '; '.join(parameters)
        components = [' ', name, '/', version, ' (', joined_parameters, ')']
        self._user_agent += ''.join(components)

    # Bucket level
    def make_bucket(self, bucket, acl = None):
        url = self._get_target_url(bucket)
        headers = {}
        conn = connectionpool.connection_from_url(self._scheme + '://' + self._location)
        response = conn.request('PUT', url, headers)
        print response

    def list_buckets(self, bucket):
        pass

    def bucket_exists(self, bucket):
        pass

    def remove_bucket(self, bucket):
        pass

    def get_bucket_acl(self, bucket):
        pass

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
            print ordered_query
            query_components = []
            for component_key in ordered_query:
                single_component = [component_key]
                if ordered_query[component_key] is not None:
                    single_component.append('=')
                    single_component.append(ordered_query[component_key])
                print single_component
                query_components.append(''.join(single_component))
                print query_components

            query_string = '&'.join(query_components)
            if query_string is not '':
                url_components.append('?')
                url_components.append(query_string)

        return ''.join(url_components)
