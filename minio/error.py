# -*- coding: utf-8 -*-
# Minio Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015, 2016, 2017 Minio, Inc.
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

:copyright: (c) 2015, 2016, 2017 by Minio, Inc.
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


class MinioError(Exception):
    """
    Base class for all exceptions

    :param message: User defined message.
    """
    def __init__(self, message, **kwargs):
        super(MinioError, self).__init__(**kwargs)
        self.message = message

    def __str__(self):
        return "{name}: message: {message}".format(
            name=self.__class__.__name__,
            message=self.message
        )

class InvalidEndpointError(MinioError):
    """
    InvalidEndpointError is raised when input endpoint URL is invalid.
    """
    pass


class InvalidBucketError(MinioError):
    """
    InvalidBucketError is raised when input bucket name is invalid.

    NOTE: Bucket names are validated based on Amazon S3 requirements.
    """
    pass


class InvalidArgumentError(MinioError):
    """
    InvalidArgumentError is raised when an unexpected
    argument is received by the callee.
    """
    pass


class InvalidSizeError(MinioError):
    """
    InvalidSizeError is raised when an unexpected size mismatch occurs.
    """
    pass


class InvalidXMLError(MinioError):
    """
    InvalidXMLError is raised when an unexpected XML tag or
    a missing tag is found during parsing.
    """
    pass


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

class ResponseError(MinioError):
    """
    ResponseError is raised when an API call doesn't succeed.
    raises :exc:`ResponseError` accordingly.

    :param response: Response from http client :class:`urllib3.HTTPResponse`.
    """
    def __init__(self, response, method, bucket_name=None,
                 object_name=None):
        super(ResponseError, self).__init__(message='')
        # initialize parameter fields
        self._response = response
        self._xml = response.data
        self.method = method
        self.bucket_name = bucket_name
        self.object_name = object_name
        # initialize all ResponseError fields
        self.code = ''
        # Amz headers
        self.request_id = ''
        self.host_id = ''
        self.region = ''

        # handle the error
        self._handle_error_response(bucket_name)

    def get_exception(self):
        """
        Gets the error exception derived from the initialization of
        an ErrorResponse object

        :return: The derived exception or ResponseError exception
        """
        exception = known_errors.get(self.code)
        if exception:
            return exception(self)
        else:
            return self

    def _handle_error_response(self, bucket_name=None):
        """
        Sets error response uses xml body if available, otherwise
        relies on HTTP headers.
        """
        if not self._response.data:
            self._set_error_response_without_body(bucket_name)
        else:
            self._set_error_response_with_body(bucket_name)

    def _set_error_response_with_body(self, bucket_name=None):
        """
        Sets all the error response fields with a valid response body.
           Raises :exc:`ValueError` if invoked on a zero length body.

        :param bucket_name: Optional bucket name resource at which error
           occurred.
        :param object_name: Option object name resource at which error
           occurred.
        """
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

    def _set_error_response_without_body(self, bucket_name=None):
        """
        Sets all the error response fields from response headers.
        """
        if self._response.status == 404:
            if bucket_name:
                if self.object_name:
                    self.code = 'NoSuchKey'
                    self.message = self._response.reason
                else:
                    self.code = 'NoSuchBucket'
                    self.message = self._response.reason
        elif self._response.status == 409:
            self.code = 'Conflict'
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


# Common error responses listed here
# http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.htmlRESTErrorResponses

class KnownResponseError(MinioError):
    def __init__(self, response_error, **kwargs):
        super(KnownResponseError, self).__init__(message=self.message, **kwargs)
        self.response_error = response_error

class AccessDenied(KnownResponseError):
    message = 'Access Denied'

class AccountProblem(KnownResponseError):
    message = 'There is a problem with your account that prevents the ' \
              'operation from completing successfully.'

class AmbiguousGrantByEmailAddress(KnownResponseError):
    message = 'The email address you provided is associated with ' \
              'more than one account.'

class BadDigest(KnownResponseError):
    message = 'The Content-MD5 you specified did not match what we received.'

class BucketAlreadyExists(KnownResponseError):
    message = 'The requested bucket name is not available. The ' \
              'bucket namespace is shared by all users of the system. ' \
              'Please select a different name and try again.'

class BucketAlreadyOwnedByYou(KnownResponseError):
    message = 'Your previous request to create the named bucket ' \
              'succeeded and you already own it.'

class BucketNotEmpty(KnownResponseError):
    message = 'The bucket you tried to delete is not empty.'

class CredentialNotSupported(KnownResponseError):
    message = 'This request does not support credentials.'

class CrossLocationLoggingProhibited(KnownResponseError):
    message = 'Cross-location logging not allowed. Buckets in one ' \
              'geographic location cannot log information to a bucket ' \
              'in another location.'

class EntityTooSmall(KnownResponseError):
    message = 'Your proposed upload is smaller than the minimum a' \
              'llowed object size.'

class EntityTooLarge(KnownResponseError):
    message = 'Your proposed upload exceeds the maximum allowed object size.'

class ExpiredToken(KnownResponseError):
    message = 'The provided token has expired.'

class IllegalVersioningConfigurationException(KnownResponseError):
    message = 'Indicates that the versioning configuration specified ' \
              'in the request is invalid.'

class IncompleteBody(KnownResponseError):
    message = 'You did not provide the number of bytes specified by the ' \
              'Content-Length HTTP header'

class IncorrectNumberOfFilesInPostRequest(KnownResponseError):
    message = 'POST requires exactly one file upload per request.'

class InlineDataTooLarge(KnownResponseError):
    message = 'Inline data exceeds the maximum allowed size.'

class InternalError(KnownResponseError):
    message = 'We encountered an internal error. Please try again.'

class InvalidAccessKeyId(KnownResponseError):
    message = 'The access key Id you provided does not exist in our records.'

class InvalidAddressingHeader(KnownResponseError):
    message = 'You must specify the Anonymous role.'

class InvalidArgument(KnownResponseError):
    message = 'Invalid Argument'

class InvalidBucketName(KnownResponseError):
    message = 'The specified bucket is not valid.'

class InvalidBucketState(KnownResponseError):
    message = 'The request is not valid with the current state of the bucket.'

class InvalidDigest(KnownResponseError):
    message = 'The Content-MD5 you specified is not valid.'

class InvalidEncryptionAlgorithmError(KnownResponseError):
    message = 'The encryption request you specified is not valid. ' \
              'The valid value is AES256.'

class InvalidLocationConstraint(KnownResponseError):
    message = 'The specified location constraint is not valid.'

class InvalidObjectState(KnownResponseError):
    message = 'The operation is not valid for the current state of the object.'

class InvalidPart(KnownResponseError):
    message = 'One or more of the specified parts could not be found. ' \
              'The part might not have been uploaded, or the specified ' \
              'entity tag might not have matched the part\'s entity tag'

class InvalidPartOrder(KnownResponseError):
    message = 'The list of parts was not in ascending order.Parts list ' \
              'must specified in order by part number.'

class InvalidPayer(KnownResponseError):
    message = 'All access to this object has been disabled.'

class InvalidPolicyDocument(KnownResponseError):
    message = 'The content of the form does not meet the conditions ' \
              'specified in the policy document.'

class InvalidRange(KnownResponseError):
    message = 'The requested range cannot be satisfied.'

class InvalidRequest(KnownResponseError):
    message = 'Invalid Request'

class InvalidSecurity(KnownResponseError):
    message = 'The provided security credentials are not valid.'

class InvalidSOAPRequest(KnownResponseError):
    message = 'The SOAP request body is invalid.'

class InvalidStorageClass(KnownResponseError):
    message = 'The storage class you specified is not valid.'

class InvalidTargetBucketForLogging(KnownResponseError):
    message = 'The target bucket for logging does not exist, ' \
              'is not owned by you, or does not have the appropriate ' \
              'grants for the log-delivery group.'

class InvalidToken(KnownResponseError):
    message = 'The provided token is malformed or otherwise invalid.'

class InvalidURI(KnownResponseError):
    message = 'Couldn\'t parse the specified URI.'

class KeyTooLong(KnownResponseError):
    message = 'Your key is too long.'

class MalformedACLError(KnownResponseError):
    message = 'The XML you provided was not well-formed ' \
              'or did not validate against our published schema.'

class MalformedPOSTRequest(KnownResponseError):
    message = 'The body of your POST request is not ' \
              'well-formed multipart/form-data.'

class MalformedXML(KnownResponseError):
    message = 'This happens when the user sends malformed xml (xml that ' \
              'doesn\'t conform to the published xsd) for the configuration.'

class MaxMessageLengthExceeded(KnownResponseError):
    message = 'Your request was too big.'

class MaxPostPreDataLengthExceededError(KnownResponseError):
    message = 'Your POST request fields preceding the ' \
              'upload file were too large.'

class MetadataTooLarge(KnownResponseError):
    message = 'Your metadata headers exceed the maximum allowed metadata size.'

class MethodNotAllowed(KnownResponseError):
    message = 'The specified method is not allowed against this resource'

class MissingAttachment(KnownResponseError):
    message = 'A SOAP attachment was expected, but none were found.'

class MissingContentLength(KnownResponseError):
    message = 'You must provide the Content-Length HTTP header.'

class MissingRequestBodyError(KnownResponseError):
    message = 'This happens when the user sends an empty xml document ' \
              'as a request. The error message is, "Request body is empty."'

class MissingSecurityElement(KnownResponseError):
    message = 'The SOAP 1.1 request is missing a security element.'

class MissingSecurityHeader(KnownResponseError):
    message = 'Your request is missing a required header.'

class NoLoggingStatusForKey(KnownResponseError):
    message = 'There is no such thing as a logging ' \
              'status subresource for a key.'

class NoSuchBucket(KnownResponseError):
    message = 'The specified bucket does not exist.'

class NoSuchKey(KnownResponseError):
    message = 'The specified key does not exist.'

class NoSuchLifecycleConfiguration(KnownResponseError):
    message = 'The lifecycle configuration does not exist.'

class NoSuchUpload(KnownResponseError):
    message = 'The specified multipart upload does not exist. ' \
              'The upload ID might be invalid, or the multipart \
              upload might have been aborted or completed.'

class NoSuchVersion(KnownResponseError):
    message = 'Indicates that the version ID specified in the ' \
              'request does not match an existing version.'

class APINotImplemented(KnownResponseError):
    message = 'A header you provided implies functionality ' \
              'that is not implemented.'

class NotSignedUp(KnownResponseError):
    message = 'Your account is not signed up.'

class NoSuchBucketPolicy(KnownResponseError):
    message = 'The specified bucket does not have a bucket policy.'

class OperationAborted(KnownResponseError):
    message = 'A conflicting conditional operation is currently in ' \
              'progress against this resource. Try again.'

class PermanentRedirect(KnownResponseError):
    message = 'The bucket you are attempting to access must be addressed ' \
              'using the specified endpoint. Send all future requests ' \
              'to this endpoint.'

class PreconditionFailed(KnownResponseError):
    message = 'At least one of the preconditions you specified did not hold.'

class Redirect(KnownResponseError):
    message = 'Temporary redirect.'

class RestoreAlreadyInProgress(KnownResponseError):
    message = 'Object restore is already in progress.'

class RequestIsNotMultiPartContent(KnownResponseError):
    message = 'Bucket POST must be of the enclosure-type multipart/form-data.'

class RequestTimeout(KnownResponseError):
    message = 'Your socket connection to the server was not read ' \
              'from or written to within the timeout period.'

class RequestTimeTooSkewed(KnownResponseError):
    message = 'The difference between the request time and the ' \
              'server\'s time is too large.'

class RequestTorrentOfBucketError(KnownResponseError):
    message = 'Requesting the torrent file of a bucket is not permitted.'

class SignatureDoesNotMatch(KnownResponseError):
    message = 'The request signature we calculated does not match the ' \
              'signature you provided.'

class ServiceUnavailable(KnownResponseError):
    message = 'Reduce your request rate.'

class SlowDown(KnownResponseError):
    message = 'Reduce your request rate.'

class TemporaryRedirect(KnownResponseError):
    message = 'You are being redirected to the bucket while DNS updates.'

class TokenRefreshRequired(KnownResponseError):
    message = 'The provided token must be refreshed.'

class TooManyBuckets(KnownResponseError):
    message = 'You have attempted to create more buckets than allowed.'

class UnexpectedContent(KnownResponseError):
    message = 'This request does not support content.'

class UnresolvableGrantByEmailAddress(KnownResponseError):
    message = 'The email address you provided does not match any account ' \
              'on record.'

class UserKeyMustBeSpecified(KnownResponseError):
    message = 'The bucket POST must contain the specified field name. ' \
              'If it is specified, check the order of the fields.'

known_errors = {
    'AccessDenied': AccessDenied,
    'AcccountProblem': AccountProblem,
    'AmbiguousGrantByEmailAddress': AmbiguousGrantByEmailAddress,
    'BadDigest': BadDigest,
    'BucketAlreadyExists': BucketAlreadyExists,
    'BucketAlreadyOwnedByYou': BucketAlreadyOwnedByYou,
    'BucketNotEmpty': BucketNotEmpty,
    'CredentialNotSupported': CredentialNotSupported,
    'CrossLocationLoggingProhibited': CrossLocationLoggingProhibited,
    'EntityTooSmall': EntityTooSmall,
    'EntityTooLarge': EntityTooLarge,
    'ExpiredToken': ExpiredToken,
    'IllegalVersioningConfigurationException': IllegalVersioningConfigurationException,
    'IncompleteBody': IncompleteBody,
    'IncorrectNumberOfFilesInPostRequest': IncorrectNumberOfFilesInPostRequest,
    'InlineDataTooLarge': InlineDataTooLarge,
    'InternalError': InternalError,
    'InvalidAccessKeyId': InvalidAccessKeyId,
    'InvalidAddressingHeader': InvalidAddressingHeader,
    'InvalidArgument': InvalidArgument,
    'InvalidBucketName': InvalidBucketName,
    'InvalidBucketState': InvalidBucketState,
    'InvalidDigest': InvalidDigest,
    'InvalidEncryptionAlgorithmError': InvalidEncryptionAlgorithmError,
    'InvalidLocationConstraint': InvalidLocationConstraint,
    'InvalidObjectState': InvalidObjectState,
    'InvalidPart': InvalidPart,
    'InvalidPartOrder': InvalidPartOrder,
    'InvalidPayer': InvalidPayer,
    'InvalidPolicyDocument': InvalidPolicyDocument,
    'InvalidRange': InvalidRange,
    'InvalidRequest': InvalidRequest,
    'InvalidSecurity': InvalidSecurity,
    'InvalidSOAPRequest': InvalidSOAPRequest,
    'InvalidStorageClass': InvalidStorageClass,
    'InvalidTargetBucketForLogging': InvalidTargetBucketForLogging,
    'InvalidToken': InvalidToken,
    'InvalidURI': InvalidURI,
    'KeyTooLong': KeyTooLong,
    'MalformedACLError': MalformedACLError,
    'MalformedPOSTRequest': MalformedPOSTRequest,
    'MalformedXML': MalformedXML,
    'MaxMessageLengthExceeded': MaxMessageLengthExceeded,
    'MaxPostPreDataLengthExceededError': MaxPostPreDataLengthExceededError,
    'MetadataTooLarge': MetadataTooLarge,
    'MethodNotAllowed': MethodNotAllowed,
    'MissingAttachment': MissingAttachment,
    'MissingContentLength': MissingContentLength,
    'MissingRequestBodyError': MissingRequestBodyError,
    'MissingSecurityElement': MissingSecurityElement,
    'MissingSecurityHeader': MissingSecurityHeader,
    'NoLoggingStatusForKey': NoLoggingStatusForKey,
    'NoSuchBucket': NoSuchBucket,
    'NoSuchKey': NoSuchKey,
    'NoSuchLifecycleConfiguration': NoSuchLifecycleConfiguration,
    'NoSuchUpload': NoSuchUpload,
    'NoSuchVersion': NoSuchVersion,
    'NotImplemented': APINotImplemented,
    'NotSignedUp': NotSignedUp,
    'NoSuchBucketPolicy': NoSuchBucketPolicy,
    'OperationAborted': OperationAborted,
    'PermanentRedirect': PermanentRedirect,
    'PreconditionFailed': PreconditionFailed,
    'Redirect': Redirect,
    'RestoreAlreadyInProgress': RestoreAlreadyInProgress,
    'RequestIsNotMultiPartContent': RequestIsNotMultiPartContent,
    'RequestTimeout': RequestTimeout,
    'RequestTimeTooSkewed': RequestTimeTooSkewed,
    'RequestTorrentOfBucketError': RequestTorrentOfBucketError,
    'SignatureDoesNotMatch': SignatureDoesNotMatch,
    'ServiceUnavailable': ServiceUnavailable,
    'SlowDown': SlowDown,
    'TemporaryRedirect': TemporaryRedirect,
    'TokenRefreshRequired': TokenRefreshRequired,
    'TooManyBuckets': TooManyBuckets,
    'UnexpectedContent': UnexpectedContent,
    'UnresolvableGrantByEmailAddress': UnresolvableGrantByEmailAddress,
    'UserKeyMustBeSpecified': UserKeyMustBeSpecified,
}
