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

This module provides custom exception classes for Minio library
and API specific errors.

:copyright: (c) 2015 by Minio, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""

from xml.etree import cElementTree
from xml.etree.cElementTree import ParseError

if hasattr(cElementTree, 'ParseError'):
    ## ParseError seems to not have .message like other
    ## exceptions. Add dynamically new attribute carrying
    ## value from message.
    if not hasattr(ParseError, 'message'):
        setattr(ParseError, 'message', ParseError.msg)
    _ETREE_EXCEPTIONS = (ParseError, AttributeError, ValueError, TypeError)
else:
    _ETREE_EXCEPTIONS = (SyntaxError, AttributeError, ValueError, TypeError)


class InvalidEndpointError(Exception):
    """
    InvalidEndpointError is raised when input endpoint URL is invalid.

    :param message: User defined message.
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
    :param message: User defined message.
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

    :param message: User defined message.
    """
    def __init__(self, message, **kwargs):
        super(InvalidArgumentError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        string_format = 'InvalidArgumentError: message: {0}'
        return string_format.format(self.message)


class InvalidSizeError(Exception):
    """
    InvalidSizeError is raised when an unexpected size mismatch occurs.

    :param message: user defined message.
    """
    def __init__(self, message, **kwargs):
        super(InvalidSizeError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        string_format = 'InvalidSizeError: message: {0}'
        return string_format.format(self.message)


class InvalidXMLError(Exception):
    """
    InvalidXMLError is raised when an unexpected XML tag or
    a missing tag is found during parsing.

    :param message: User defined message.
    """
    def __init__(self, message, **kwargs):
        super(InvalidXMLError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        string_format = 'InvalidXMLError: message: {0}'
        return string_format.format(self.message)


class MultiDeleteError(object):
    """
    Represents an error raised when trying to delete an object in a
    Multi-Object Delete API call :class:`MultiDeleteError <MultiDeleteError>`

    :object_name: Object name that had a delete error.
    :error_code: Error code.
    :error_message: Error message.
    """
    def __init__(self, object_name, err_code, err_message):
        self.object_name = object_name
        self.error_code = err_code
        self.error_message = err_message

    def __str__(self):
        string_format = '<MultiDeleteError: object_name: {} error_code: {}' \
                        ' error_message: {}>'
        return string_format.format(self.object_name,
                                    self.error_code,
                                    self.error_message)


class ResponseError(Exception):
    """
    ResponseError is raised when an API call doesn't succeed.
    raises :exc:`ResponseError` accordingly.

    :param response: Response from http client :class:`urllib3.HTTPResponse`.
    """
    def __init__(self, response, **kwargs):
        super(ResponseError, self).__init__(**kwargs)
        self._response = response
        # Initialize all the ResponseError fields.
        self.method = ''
        self.code = ''
        self.message = ''
        self.bucket_name = ''
        self.object_name = ''
        # Amz headers
        self.request_id = ''
        self.host_id = ''
        self.region = ''
        # Ends.

        # Additional copy of XML response for future use.
        self._xml = response.data

    def head(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for head request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self.method = 'HEAD'
        self._set_error_response(bucket_name, object_name)

        return self

    def delete(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for delete request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self.method = 'DELETE'
        self._set_error_response(bucket_name, object_name)

        return self

    def get(self, bucket_name=None, object_name=None):
        """
        Generates :exc:`ResponseError` specific for get request.

        :param bucket_name: Bucket name on which the error occurred, optional.
        :param object_name: Object name on which the error occurred, optional.
        """
        self.method = 'GET'
        self._set_error_response(bucket_name, object_name)

        return self

    def put(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for put request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self.method = 'PUT'
        self._set_error_response(bucket_name, object_name)

        return self

    def post(self, bucket_name, object_name=None):
        """
        Generates :exc:`ResponseError` specific for post request.

        :param bucket_name: Bucket name on which the error occurred.
        :param object_name: Object name on which the error occurred, optional.
        """
        self.method = 'POST'
        self._set_error_response(bucket_name, object_name)

        return self

    def _set_error_response(self, bucket_name=None, object_name=None):
        """
        Sets error response uses xml body if available, otherwise
        relies on HTTP headers.
        """
        if not self._response.data:
            self._set_error_response_without_body(bucket_name, object_name)
        else:
            self._set_error_response_with_body(bucket_name, object_name)

    def _set_error_response_with_body(self, bucket_name=None,
                                      object_name=None):
        """
        Sets all the error response fields with a valid response body.
           Raises :exc:`ValueError` if invoked on a zero length body.

        :param bucket_name: Optional bucket name resource at which error
           occurred.
        :param object_name: Option object name resource at which error
           occurred.
        """
        self.bucket_name = bucket_name
        self.object_name = object_name

        if len(self._response.data) == 0:
            raise ValueError('response data has no body.')
        try:
            root = cElementTree.fromstring(self._response.data)
        except _ETREE_EXCEPTIONS as error:
            raise InvalidXMLError('"Error" XML is not parsable. '
                                  'Message: {0}'.format(error.message))
        for attribute in root:
            if attribute.tag == 'Code':
                self.code = attribute.text
            elif attribute.tag == 'BucketName':
                self.bucket_name = attribute.text
            elif attribute.tag == 'Key':
                self.object_name = attribute.text
            elif attribute.tag == 'Message':
                self.message = attribute.text
            elif attribute.tag == 'RequestId':
                self.request_id = attribute.text
            elif attribute.tag == 'HostId':
                self.host_id = attribute.text
        # Set amz headers.
        self._set_amz_headers()

    def _set_error_response_without_body(self, bucket_name=None,
                                         object_name=None):
        """
        Sets all the error response fields from response headers.

        :param bucket_name: Optional bucket name resource at which error
           occurred.
        :param object_name: Option object name resource at which error
           occurred.
        """
        self.bucket_name = bucket_name
        self.object_name = object_name

        if self._response.status == 404:
            if bucket_name:
                if object_name:
                    self.code = 'NoSuchKey'
                    self.message = self._response.reason
                else:
                    self.code = 'NoSuchBucket'
                    self.message = self._response.reason
        elif self._response.status == 409:
            self.code = 'Confict'
            self.message = 'The bucket you tried to delete is not empty.'
        elif self._response.status == 403:
            self.code = 'AccessDenied'
            self.message = self._response.reason
        elif self._response.status == 400:
            self.code = 'BadRequest'
            self.message = self._response.reason
        elif self._response.status == 301:
            self.code = 'PermanentRedirect'
            self.message = self._response.reason
        elif self._response.status == 307:
            self.code = 'Redirect'
            self.message = self._response.reason
        elif self._response.status in [405, 501]:
            self.code = 'MethodNotAllowed'
            self.message = self._response.reason
        elif self._response.status == 500:
            self.code = 'InternalError'
            self.message = 'Internal Server Error.'
        else:
            self.code = 'UnknownException'
            self.message = self._response.reason
        # Set amz headers.
        self._set_amz_headers()

    def _set_amz_headers(self):
        """
        Sets x-amz-* error response fields from response headers.
        """
        if self._response.headers:
            # keeping x-amz-id-2 as part of amz_host_id.
            if 'x-amz-id-2' in self._response.headers:
                self.host_id = self._response.headers['x-amz-id-2']
            if 'x-amz-request-id' in self._response.headers:
                self.request_id = self._response.headers['x-amz-request-id']
            # This is a new undocumented field, set only if available.
            if 'x-amz-bucket-region' in self._response.headers:
                self.region = self._response.headers['x-amz-bucket-region']

    def __str__(self):
        return ('ResponseError: code: {0}, message: {1},'
                ' bucket_name: {2}, object_name: {3}, request_id: {4},'
                ' host_id: {5}, region: {6}'.format(self.code,
                                                    self.message,
                                                    self.bucket_name,
                                                    self.object_name,
                                                    self.request_id,
                                                    self.host_id,
                                                    self.region))
