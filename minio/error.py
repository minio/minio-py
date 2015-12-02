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
minio.error
~~~~~~~~~~~~~~~~~~~

This module provides custom exception classes for Minio library and API specific errors.
"""

from xml.etree import cElementTree

class InvalidEndpointError(Exception):
    """
    InvalidEndpointError is raised when input endpoint URL is invalid.
    """
    def __init__(self, message, **kwargs):
        super(InvalidEndpointError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        string_format = 'InvalidEndpointError: message: {0}'
        return string_format.format(self.message)

class InvalidBucketError(Exception):
    """
    InvalidBucketError is raised when input bucket name is invalid.

    NOTE: Bucket names are validated based on Amazon S3 requirements.
    """
    def __init__(self, message, **kwargs):
        super(InvalidBucketError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        string_format = 'InvalidBucketError: message: {0}'
        return string_format.format(self.message)

class InvalidArgumentError(Exception):
    """
    InvalidArgumentError is raised when an unexpected
    argument is received by the callee.
    """
    def __init__(self, message, **kwargs):
        super(InvalidArgumentError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        string_format = 'InvalidArgumentError: message: {0}'
        return string_format.format(self.message)

class ResponseError(Exception):
    """
    ResponseError is raised when an API call doesn't succeed.
    To indicate a successful status each API verifies 2xx, 3xx
    and raises :exc:`ResponseError` accordingly.

    :param response: Response from http client :class:`urllib3.HTTPResponse`.
    """
    def __init__(self, response, **kwargs):
        super(ResponseError, self).__init__(**kwargs)
        self._response = response
        ### Initialize all the ResponseError fields.
        self.code = ''
        self.message = ''
        self.resource = ''
        ## Amz headers
        self.request_id = ''
        self.host_id = ''
        self.region = ''
        ## Ends.

        ### Additional copy of XML response for future use.
        self._xml = response.data

    def head(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for head request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self._set_resource(bucket_name, object_name)
        self._set_amz_headers()
        self._set_error_response()
        raise self

    def delete(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for delete request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self._set_resource(bucket_name, object_name)
        self._set_amz_headers()
        self._set_error_response()
        raise self

    def get(self, bucket_name=None, object_name=None):
        """
        Generates :exc:`ResponseError` specific for get request.

        :param bucket_name: Bucket name on which the error occurred, optional.
        :param object_name: Object name on which the error occurred, optional.
        """
        self._set_resource(bucket_name, object_name)
        self._set_amz_headers()
        self._set_error_response()
        raise self

    def put(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for put request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self._set_resource(bucket_name, object_name)
        self._set_amz_headers()
        self._set_error_response()
        raise self

    def post(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for post request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self._set_resource(bucket_name, object_name)
        self._set_amz_headers()
        self._set_error_response()
        raise self

    def _set_error_response(self):
        """
        Sets error response uses xml body if available, otherwise
        relies on HTTP headers.
        """
        if len(self._response.data) == 0:
            self._set_error_response_without_body()
        else:
            self._set_error_response_with_body()

    def _set_resource(self, bucket_name=None, object_name=None):
        """
        Set resource response field.

        :param bucket_name: Optional bucket name resource at which error occurred.
        :param object_name: Option object name resource at which error occurred.
        """
        if bucket_name is not None:
            self.resource = bucket_name
        if bucket_name is not None and object_name is not None:
            self.resource = bucket_name + '/' + object_name

    def _set_error_response_with_body(self):
        """
        Sets all the error response fields with a valid response body.
           Raises :exc:`ValueError` if invoked on a zero length body.
        """
        if len(self._response.data) == 0:
            raise ValueError('response data has no body.')
        root = cElementTree.fromstring(self._response.data)
        for attribute in root:
            if attribute.tag == 'Code':
                self.code = attribute.text
            if attribute.tag == 'Message':
                self.message = attribute.text
            if attribute.tag == 'RequestId':
                self.request_id = attribute.text
            if attribute.tag == 'HostId':
                self.host_id = attribute.text

    def _set_error_response_without_body(self):
        """
        Sets all the error response fields from response headers.
        """
        if self._response.status == 404:
            if object_name is None:
                self.code = 'BucketNotFoundException'
                self.message = self._response.reason
            else:
                self.code = 'ObjectNotFoundException'
                self.message = self._response.reason
        elif self._response.status == 403:
            self.code = 'AccessDeniedException'
            self.message = self._response.reason
        elif self._response.status == 400:
            self.code = 'BadRequestException'
            self.message = self._response.reason
        elif self._response.status == 301 or self._response.status == 307:
            self.code = 'RedirectException'
            self.message = self._response.reason
        elif self._response.status == 405 or response.status == 501:
            self.code = 'MethodNotAllowedException'
            self.message = self._response.reason
        else:
            self.code = 'UnknownException'
            self.message = self._response.reason

    def _set_amz_headers(self):
        """
        Sets x-amz-* error response fields from response headers.
        """
        if self._response.headers is not None:
            ## keeping x-amz-id-2 as part of amz_host_id.
            if 'x-amz-id-2' in self._response.headers:
                self._host_id = self._response.headers['x-amz-id-2']
            if 'x-amz-request-id' in self._response.headers:
                self._request_id = self._response.headers['x-amz-request-id']
            ## This is a new undocumented field, set only if available.
            if 'x-amz-bucket-region' in self._response.headers:
                self._region = self._response.headers['x-amz-bucket-region']

    def __str__(self):
        return 'ResponseError: code: {0}, message: {1},' \
            ' resource: {2}, request_id: {3}, host_id: {4},' \
            ' region: {5}'.format(self.code,
                                  self.message,
                                  self.resource,
                                  self.request_id,
                                  self.host_id,
                                  self.region)
