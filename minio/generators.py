# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage, (C) 2015 Minio, Inc.
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
minio.generators
~~~~~~~~~~~~~~~~~~~

This module contains core iterators.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from .error import ResponseError
from .helpers import get_target_url
from .parsers import (parse_list_objects, parse_list_multipart_uploads,
                      parse_list_parts)

from .signer import sign_v4


class ListObjectsIterator(object):
    """
    Implements list objects iterator for list objects parser.

    :param client: Takes instance of :meth:`urllib3.PoolManager`
    :param url: Target endpoint url where request is served to.
    :param bucket_name: Bucket name resource where request will be served from.
    :param prefix: Prefix name resource for filtering objects.
    :param recursive: Default is non recursive, set True lists all objects
       iteratively.
    :param access_key: Optional if provided requests will be authenticated.
    :param secret_key: Optional if provided requests will be authenticated.
    :param region: Optional if provided requests will be served to this region.
    """
    def __init__(self, client, url, bucket_name, prefix, recursive,
                 access_key=None, secret_key=None, region='us-east-1'):
        self._http = client
        self._endpoint_url = url
        self._bucket_name = bucket_name
        self._prefix = prefix
        self._recursive = recursive
        self._results = []
        self._complete = False
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region
        self._is_truncated = True
        self._marker = None

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        # if complete, end iteration
        if self._complete:
            raise StopIteration
        # if not truncated and we've emitted everything, end iteration
        if len(self._results) == 0 and self._is_truncated is False:
            self._complete = True
            raise StopIteration
        # perform another fetch
        if len(self._results) == 0:
            self._results, self._is_truncated, self._marker = self._fetch()
        # if fetch results in no elements, end iteration
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        # return result
        return self._results.pop(0)

    def _fetch(self):
        query = {}
        query['max-keys'] = 1000
        if self._prefix is not None:
            query['prefix'] = self._prefix
        if not self._recursive:
            query['delimiter'] = '/'
        if self._marker is not None:
            query['marker'] = self._marker

        url = get_target_url(self._endpoint_url,
                             bucket_name=self._bucket_name, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=self._region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get(self._bucket_name)

        return parse_list_objects(response.data, bucket_name=self._bucket_name)


class ListIncompleteUploadsIterator(object):
    """
    Implements list incomplete uploads iterator for list multipart uploads
    parser.

    :param client: Takes instance of :meth:`urllib3.PoolManager`
    :param url: Target endpoint url where request is served to.
    :param bucket_name: Bucket name resource where request will be served from.
    :param prefix: Prefix name resource for filtering objects.
    :param delimiter: Default is non recursive, set to *None* to be recursive.
    :param access_key: Optional if provided requests will be authenticated.
    :param secret_key: Optional if provided requests will be authenticated.
    :param region: Optional if provided requests will be served to this region.
    """
    def __init__(self, client, url, bucket_name, prefix=None, delimiter='/',
                 access_key=None, secret_key=None, region='us-east-1'):
        # from user
        self._http = client
        self._endpoint_url = url
        self._bucket_name = bucket_name
        self._prefix = prefix
        self._delimiter = delimiter
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region

        # internal variables
        self._results = []
        self._complete = False
        self._is_truncated = True
        self._key_marker = None
        self._upload_id_marker = None

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        # if complete, end iteration
        if self._complete:
            raise StopIteration
        # if not truncated and we've emitted everything, end iteration
        if len(self._results) == 0 and self._is_truncated is False:
            self._complete = True
            raise StopIteration
        # perform another fetch
        if len(self._results) == 0:
            self._results, self._is_truncated, self._key_marker, \
                self._upload_id_marker = self._fetch()
        # if fetch results in no elements, end iteration
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        # return result
        return self._results.pop(0)

    def _fetch(self):
        query = {
            'uploads': None
        }
        query['max-uploads'] = 1000
        if self._prefix is not None:
            query['prefix'] = self._prefix
        if self._key_marker is not None:
            query['key-marker'] = self._key_marker
        if self._upload_id_marker is not None:
            query['upload-id-marker'] = self._upload_id_marker
        if self._delimiter is not None:
            query['delimiter'] = self._delimiter

        url = get_target_url(self._endpoint_url,
                             bucket_name=self._bucket_name, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=self._region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get(self._bucket_name)

        return parse_list_multipart_uploads(response.data,
                                            bucket_name=self._bucket_name)


class ListUploadPartsIterator(object):
    """
    Implements list upload parts iterator for list parts parser.

    :param client: Takes instance of :meth:`urllib3.PoolManager`
    :param url: Target endpoint url where request is served to.
    :param bucket_name: Bucket name resource where request will be served from.
    :param object_name: Object name resource where request will be served from.
    :param upload_id: Upload ID of active multipart to be served.
    :param access_key: Optional if provided requests will be authenticated.
    :param secret_key: Optional if provided requests will be authenticated.
    :param region: Optional if provided requests will be served to this region.
    """
    def __init__(self, client, url, bucket_name, object_name, upload_id,
                 access_key=None, secret_key=None, region='us-east-1'):
        # from user
        self._http = client
        self._endpoint_url = url
        self._bucket_name = bucket_name
        self._object_name = object_name
        self._upload_id = upload_id
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region

        # internal variables
        self._results = []
        self._complete = False
        self._is_truncated = True
        self._part_marker = None

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        # if complete, end iteration
        if self._complete:
            raise StopIteration
        # if not truncated and we've emitted everything, end iteration
        if len(self._results) == 0 and self._is_truncated is False:
            self._complete = True
            raise StopIteration
        # perform another fetch
        if len(self._results) == 0:
            (self._results,
             self._is_truncated,
             self._part_marker) = self._fetch()
        # if fetch results in no elements, end iteration
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        # return result
        potential_result = self._results.pop(0)
        if self._object_name is None:
            return potential_result
        if potential_result.object_name == self._object_name:
            return potential_result
        self._complete = True
        raise StopIteration

    def _fetch(self):
        query = {
            'uploadId': self._upload_id
        }
        query['max-parts'] = 1000
        if self._part_marker is not None:
            query['part-number-marker'] = self._part_marker

        url = get_target_url(self._endpoint_url,
                             bucket_name=self._bucket_name,
                             object_name=self._object_name,
                             query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=self._region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            response_error = ResponseError(response)
            raise response_error.get(self._bucket_name, self._object_name)

        parts = parse_list_parts(response.data,
                                 bucket_name=self._bucket_name,
                                 object_name=self._object_name,
                                 upload_id=self._upload_id)

        return parts
