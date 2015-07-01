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
import cgi
import collections

__author__ = 'minio'


def get_target_url(scheme, location, bucket=None, key=None, query=None):
    url_components = [scheme, '://', location, '/']

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
                single_component.append(cgi.escape(str(ordered_query[component_key])).replace('/', '%2F'))
            query_components.append(''.join(single_component))

        query_string = '&'.join(query_components)
        if query_string is not '':
            url_components.append('?')
            url_components.append(query_string)

    return ''.join(url_components)


def is_non_empty_string(name, input_string):
    if not isinstance(input_string, basestring):
        raise TypeError(name)
    input_string = input_string.strip()
    if input_string == '':
        raise ValueError(name)


def is_positive_int(name, input_int, include_zero=False):
    if not isinstance(input_int, int):
        raise TypeError(name)
    if include_zero and input_int < 0:
        raise ValueError(name)
    if not include_zero and input_int <= 0:
        raise ValueError(name)
