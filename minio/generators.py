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

from .helpers import get_target_url
from .parsers import (parse_list_objects, parse_error,
                      parse_incomplete_uploads, parse_uploaded_parts)
from .signer import sign_v4

class ListObjectsIterator(object):
    def __init__(self, client, url, bucketName, prefix,
                 recursive, access_key=None, secret_key=None, region='us-east-1'):
        self._http = client
        self._endpoint_url = url
        self._bucketName = bucketName
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

        url = get_target_url(self._endpoint_url, bucketName=self._bucketName, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=self._region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, self._bucketName)

        return parse_list_objects(response.data, bucketName=self._bucketName)


class ListIncompleteUploadsIterator(object):
    def __init__(self, client, url, bucketName, objectName=None, delimiter=None,
                 access_key=None, secret_key=None, region='us-east-1'):
        # from user
        self._http = client
        self._endpoint_url = url
        self._bucketName = bucketName
        self._objectName = objectName
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
        if self._objectName is not None:
            query['prefix'] = self._objectName
        if self._key_marker is not None:
            query['key-marker'] = self._key_marker
        if self._upload_id_marker is not None:
            query['upload-id-marker'] = self._upload_id_marker
        if self._delimiter is not None:
            query['delimiter'] = self._delimiter

        url = get_target_url(self._endpoint_url, bucketName=self._bucketName, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=self._region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, self._bucketName)

        return parse_incomplete_uploads(response.data, bucketName=self._bucketName)


class ListUploadPartsIterator(object):
    def __init__(self, client, url, bucketName, objectName, upload_id,
                 access_key=None, secret_key=None, region='us-east-1'):
        # from user
        self._http = client
        self._endpoint_url = url
        self._bucketName = bucketName
        self._objectName = objectName
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
            self._results, self._is_truncated, self._part_marker = self._fetch()
        # if fetch results in no elements, end iteration
        if len(self._results) == 0:
            self._complete = True
            raise StopIteration
        # return result
        potential_result = self._results.pop(0)
        if self._objectName is None:
            return potential_result
        if potential_result.objectName == self._objectName:
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

        url = get_target_url(self._endpoint_url, bucketName=self._bucketName,
                             objectName=self._objectName, query=query)

        method = 'GET'
        headers = {}

        headers = sign_v4(method=method, url=url,
                          region=self._region,
                          headers=headers,
                          access_key=self._access_key,
                          secret_key=self._secret_key)

        response = self._http.request(method, url, headers=headers)

        if response.status != 200:
            parse_error(response, self._bucketName+"/"+self._objectName)

        return parse_uploaded_parts(response.data, bucketName=self._bucketName,
                                    objectName=self._objectName, upload_id=self._upload_id)
