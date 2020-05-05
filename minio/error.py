# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) 2015-2019 MinIO, Inc.
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

# pylint: disable=too-many-lines

"""
minio.error
~~~~~~~~~~~~~~~~~~~

This module provides custom exception classes for MinIO library
and API specific errors.

:copyright: (c) 2015, 2016, 2017 by MinIO, Inc.
:license: Apache 2.0, see LICENSE for more details.

"""
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError


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


class InvalidBucketError(MinioError):
    """
    InvalidBucketError is raised when input bucket name is invalid.

    NOTE: Bucket names are validated based on Amazon S3 requirements.
    """


class InvalidArgumentError(MinioError):
    """
    InvalidArgumentError is raised when an unexpected
    argument is received by the callee.
    """


class InvalidSizeError(MinioError):
    """
    InvalidSizeError is raised when an unexpected size mismatch occurs.
    """


class InvalidXMLError(MinioError):
    """
    InvalidXMLError is raised when an unexpected XML tag or
    a missing tag is found during parsing.
    """


class MultiDeleteError(MinioError):
    """
    Represents an error raised when trying to delete an object in a
    Multi-Object Delete API call :class:`MultiDeleteError <MultiDeleteError>`

    :object_name: Object name that had a delete error.
    :error_code: Error code.
    :error_message: Error message.
    """

    def __init__(self, object_name, err_code, err_message):
        super(MultiDeleteError, self).__init__(err_message)
        self.object_name = object_name
        self.error_code = err_code
        self.error_message = err_message

    def __str__(self):
        string_format = ('<MultiDeleteError: object_name: {} error_code: {}'
                         ' error_message: {}>')
        return string_format.format(self.object_name,
                                    self.error_code,
                                    self.error_message)


class KnownResponseError(MinioError):
    """
    Common error responses listed in
    http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html#RESTErrorResponses
    """

    def __init__(self, response_error, **kwargs):
        super(KnownResponseError, self).__init__(
            message=self.message, **kwargs)
        self.response_error = response_error


class AccessDenied(KnownResponseError):
    """AccessDenied S3 error."""
    message = 'Access Denied'

    def __init__(self):
        super(AccessDenied, self).__init__(self.message)


class AccountProblem(KnownResponseError):
    """AcccountProblem S3 error."""
    message = ('There is a problem with your account that prevents the '
               'operation from completing successfully.')

    def __init__(self):
        super(AccountProblem, self).__init__(self.message)


class AmbiguousGrantByEmailAddress(KnownResponseError):
    """AmbiguousGrantByEmailAddress S3 error."""
    message = ('The email address you provided is associated with '
               'more than one account.')

    def __init__(self):
        super(AmbiguousGrantByEmailAddress, self).__init__(self.message)


class BadDigest(KnownResponseError):
    """BadDigest S3 error."""
    message = 'The Content-MD5 you specified did not match what we received.'

    def __init__(self):
        super(BadDigest, self).__init__(self.message)


class BucketAlreadyExists(KnownResponseError):
    """BucketAlreadyExists S3 error."""
    message = ('The requested bucket name is not available. The '
               'bucket namespace is shared by all users of the system. '
               'Please select a different name and try again.')

    def __init__(self):
        super(BucketAlreadyExists, self).__init__(self.message)


class BucketAlreadyOwnedByYou(KnownResponseError):
    """BucketAlreadyOwnedByYou S3 error."""
    message = ('Your previous request to create the named bucket '
               'succeeded and you already own it.')

    def __init__(self):
        super(BucketAlreadyOwnedByYou, self).__init__(self.message)


class BucketNotEmpty(KnownResponseError):
    """BucketNotEmpty S3 error."""
    message = 'The bucket you tried to delete is not empty.'

    def __init__(self):
        super(BucketNotEmpty, self).__init__(self.message)


class CredentialNotSupported(KnownResponseError):
    """CredentialNotSupported S3 error."""
    message = 'This request does not support credentials.'

    def __init__(self):
        super(CredentialNotSupported, self).__init__(self.message)


class CrossLocationLoggingProhibited(KnownResponseError):
    """CrossLocationLoggingProhibited S3 error."""
    message = ('Cross-location logging not allowed. Buckets in one '
               'geographic location cannot log information to a bucket '
               'in another location.')

    def __init__(self):
        super(CrossLocationLoggingProhibited, self).__init__(self.message)


class EntityTooSmall(KnownResponseError):
    """EntityTooSmall S3 error."""
    message = ('Your proposed upload is smaller than the minimum '
               'allowed object size.')

    def __init__(self):
        super(EntityTooSmall, self).__init__(self.message)


class EntityTooLarge(KnownResponseError):
    """EntityTooLarge S3 error."""
    message = 'Your proposed upload exceeds the maximum allowed object size.'

    def __init__(self):
        super(EntityTooLarge, self).__init__(self.message)


class ExpiredToken(KnownResponseError):
    """ExpiredToken S3 error."""
    message = 'The provided token has expired.'

    def __init__(self):
        super(ExpiredToken, self).__init__(self.message)


class IllegalVersioningConfigurationException(KnownResponseError):
    """IllegalVersioningConfigurationException S3 error."""
    message = ('Indicates that the versioning configuration specified '
               'in the request is invalid.')

    def __init__(self):
        super(IllegalVersioningConfigurationException, self).__init__(
            self.message)


class IncompleteBody(KnownResponseError):
    """IncompleteBody S3 error."""
    message = ('You did not provide the number of bytes specified by the '
               'Content-Length HTTP header')

    def __init__(self):
        super(IncompleteBody, self).__init__(self.message)


class IncorrectNumberOfFilesInPostRequest(KnownResponseError):
    """IncorrectNumberOfFilesInPostRequest S3 error."""
    message = 'POST requires exactly one file upload per request.'

    def __init__(self):
        super(IncorrectNumberOfFilesInPostRequest, self).__init__(self.message)


class InlineDataTooLarge(KnownResponseError):
    """InlineDataTooLarge S3 error."""
    message = 'Inline data exceeds the maximum allowed size.'

    def __init__(self):
        super(InlineDataTooLarge, self).__init__(self.message)


class InternalError(KnownResponseError):
    """InternalError S3 error."""
    message = 'We encountered an internal error. Please try again.'

    def __init__(self):
        super(InternalError, self).__init__(self.message)


class InvalidAccessKeyId(KnownResponseError):
    """InvalidAccessKeyId S3 error."""
    message = 'The access key Id you provided does not exist in our records.'

    def __init__(self):
        super(InvalidAccessKeyId, self).__init__(self.message)


class InvalidAddressingHeader(KnownResponseError):
    """InvalidAddressingHeader S3 error."""
    message = 'You must specify the Anonymous role.'

    def __init__(self):
        super(InvalidAddressingHeader, self).__init__(self.message)


class InvalidArgument(KnownResponseError):
    """InvalidArgument S3 error."""
    message = 'Invalid Argument'

    def __init__(self):
        super(InvalidArgument, self).__init__(self.message)


class InvalidBucketName(KnownResponseError):
    """InvalidBucketName S3 error."""
    message = 'The specified bucket is not valid.'

    def __init__(self):
        super(InvalidBucketName, self).__init__(self.message)


class InvalidBucketState(KnownResponseError):
    """InvalidBucketState S3 error."""
    message = 'The request is not valid with the current state of the bucket.'

    def __init__(self):
        super(InvalidBucketState, self).__init__(self.message)


class InvalidDigest(KnownResponseError):
    """InvalidDigest S3 error."""
    message = 'The Content-MD5 you specified is not valid.'

    def __init__(self):
        super(InvalidDigest, self).__init__(self.message)


class InvalidEncryptionAlgorithmError(KnownResponseError):
    """InvalidEncryptionAlgorithmError S3 error."""
    message = ('The encryption request you specified is not valid. '
               'The valid value is AES256.')

    def __init__(self):
        super(InvalidEncryptionAlgorithmError, self).__init__(self.message)


class InvalidLocationConstraint(KnownResponseError):
    """InvalidLocationConstraint S3 error."""
    message = 'The specified location constraint is not valid.'

    def __init__(self):
        super(InvalidLocationConstraint, self).__init__(self.message)


class InvalidObjectState(KnownResponseError):
    """InvalidObjectState S3 error."""
    message = 'The operation is not valid for the current state of the object.'

    def __init__(self):
        super(InvalidObjectState, self).__init__(self.message)


class InvalidPart(KnownResponseError):
    """InvalidPart S3 error."""
    message = ('One or more of the specified parts could not be found. '
               'The part might not have been uploaded, or the specified '
               'entity tag might not have matched the part\'s entity tag')

    def __init__(self):
        super(InvalidPart, self).__init__(self.message)


class InvalidPartOrder(KnownResponseError):
    """InvalidPartOrder S3 error."""
    message = ('The list of parts was not in ascending order.Parts list '
               'must specified in order by part number.')

    def __init__(self):
        super(InvalidPartOrder, self).__init__(self.message)


class InvalidPayer(KnownResponseError):
    """InvalidPayer S3 error."""
    message = 'All access to this object has been disabled.'

    def __init__(self):
        super(InvalidPayer, self).__init__(self.message)


class InvalidPolicyDocument(KnownResponseError):
    """InvalidPolicyDocument S3 error."""
    message = ('The content of the form does not meet the conditions '
               'specified in the policy document.')

    def __init__(self):
        super(InvalidPolicyDocument, self).__init__(self.message)


class InvalidRange(KnownResponseError):
    """InvalidRange S3 error."""
    message = 'The requested range cannot be satisfied.'

    def __init__(self):
        super(InvalidRange, self).__init__(self.message)


class InvalidRequest(KnownResponseError):
    """InvalidRequest S3 error."""
    message = 'Invalid Request'

    def __init__(self):
        super(InvalidRequest, self).__init__(self.message)


class InvalidSecurity(KnownResponseError):
    """InvalidSecurity S3 error."""
    message = 'The provided security credentials are not valid.'

    def __init__(self):
        super(InvalidSecurity, self).__init__(self.message)


class InvalidSOAPRequest(KnownResponseError):
    """InvalidSOAPRequest S3 error."""
    message = 'The SOAP request body is invalid.'

    def __init__(self):
        super(InvalidSOAPRequest, self).__init__(self.message)


class InvalidStorageClass(KnownResponseError):
    """InvalidStorageClass S3 error."""
    message = 'The storage class you specified is not valid.'

    def __init__(self):
        super(InvalidStorageClass, self).__init__(self.message)


class InvalidTargetBucketForLogging(KnownResponseError):
    """InvalidTargetBucketForLogging S3 error."""
    message = ('The target bucket for logging does not exist, '
               'is not owned by you, or does not have the appropriate '
               'grants for the log-delivery group.')

    def __init__(self):
        super(InvalidTargetBucketForLogging, self).__init__(self.message)


class InvalidToken(KnownResponseError):
    """InvalidToken S3 error."""
    message = 'The provided token is malformed or otherwise invalid.'

    def __init__(self):
        super(InvalidToken, self).__init__(self.message)


class InvalidURI(KnownResponseError):
    """InvalidURI S3 error."""
    message = 'Couldn\'t parse the specified URI.'

    def __init__(self):
        super(InvalidURI, self).__init__(self.message)


class KeyTooLong(KnownResponseError):
    """KeyTooLong S3 error."""
    message = 'Your key is too long.'

    def __init__(self):
        super(KeyTooLong, self).__init__(self.message)


class MalformedACLError(KnownResponseError):
    """MalformedACLError S3 error."""
    message = ('The XML you provided was not well-formed '
               'or did not validate against our published schema.')

    def __init__(self):
        super(MalformedACLError, self).__init__(self.message)


class MalformedPOSTRequest(KnownResponseError):
    """MalformedPOSTRequest S3 error."""
    message = ('The body of your POST request is not '
               'well-formed multipart/form-data.')

    def __init__(self):
        super(MalformedPOSTRequest, self).__init__(self.message)


class MalformedXML(KnownResponseError):
    """MalformedXML S3 error."""
    message = ("This happens when the user sends malformed xml (xml that "
               "doesn't conform to the published xsd) for the configuration.")

    def __init__(self):
        super(MalformedXML, self).__init__(self.message)


class MaxMessageLengthExceeded(KnownResponseError):
    """MaxMessageLengthExceeded S3 error."""
    message = 'Your request was too big.'

    def __init__(self):
        super(MaxMessageLengthExceeded, self).__init__(self.message)


class MaxPostPreDataLengthExceededError(KnownResponseError):
    """MaxPostPreDataLengthExceededError S3 error."""
    message = ('Your POST request fields preceding the '
               'upload file were too large.')

    def __init__(self):
        super(MaxPostPreDataLengthExceededError, self).__init__(self.message)


class MetadataTooLarge(KnownResponseError):
    """MetadataTooLarge S3 error."""
    message = 'Your metadata headers exceed the maximum allowed metadata size.'

    def __init__(self):
        super(MetadataTooLarge, self).__init__(self.message)


class MethodNotAllowed(KnownResponseError):
    """MethodNotAllowed S3 error."""
    message = 'The specified method is not allowed against this resource'

    def __init__(self):
        super(MethodNotAllowed, self).__init__(self.message)


class MissingAttachment(KnownResponseError):
    """MissingAttachment S3 error."""
    message = 'A SOAP attachment was expected, but none were found.'

    def __init__(self):
        super(MissingAttachment, self).__init__(self.message)


class MissingContentLength(KnownResponseError):
    """MissingContentLength S3 error."""
    message = 'You must provide the Content-Length HTTP header.'

    def __init__(self):
        super(MissingContentLength, self).__init__(self.message)


class MissingRequestBodyError(KnownResponseError):
    """MissingRequestBodyError S3 error."""
    message = ('This happens when the user sends an empty xml document '
               'as a request. The error message is, "Request body is empty."')

    def __init__(self):
        super(MissingRequestBodyError, self).__init__(self.message)


class MissingSecurityElement(KnownResponseError):
    """MissingSecurityElement S3 error."""
    message = 'The SOAP 1.1 request is missing a security element.'

    def __init__(self):
        super(MissingSecurityElement, self).__init__(self.message)


class MissingSecurityHeader(KnownResponseError):
    """MissingSecurityHeader S3 error."""
    message = 'Your request is missing a required header.'

    def __init__(self):
        super(MissingSecurityHeader, self).__init__(self.message)


class NoLoggingStatusForKey(KnownResponseError):
    """NoLoggingStatusForKey S3 error."""
    message = ('There is no such thing as a logging '
               'status subresource for a key.')

    def __init__(self):
        super(NoLoggingStatusForKey, self).__init__(self.message)


class NoSuchBucket(KnownResponseError):
    """NoSuchBucket S3 error."""
    message = 'The specified bucket does not exist.'

    def __init__(self):
        super(NoSuchBucket, self).__init__(self.message)


class NoSuchKey(KnownResponseError):
    """NoSuchKey S3 error."""
    message = 'The specified key does not exist.'

    def __init__(self):
        super(NoSuchKey, self).__init__(self.message)


class NoSuchLifecycleConfiguration(KnownResponseError):
    """NoSuchLifecycleConfiguration S3 error."""
    message = 'The lifecycle configuration does not exist.'

    def __init__(self):
        super(NoSuchLifecycleConfiguration, self).__init__(self.message)


class NoSuchUpload(KnownResponseError):
    """NoSuchUpload S3 error."""
    message = ('The specified multipart upload does not exist. '
               'The upload ID might be invalid, or the multipart '
               'upload might have been aborted or completed.')

    def __init__(self):
        super(NoSuchUpload, self).__init__(self.message)


class NoSuchVersion(KnownResponseError):
    """NoSuchVersion S3 error."""
    message = ('Indicates that the version ID specified in the '
               'request does not match an existing version.')

    def __init__(self):
        super(NoSuchVersion, self).__init__(self.message)


class APINotImplemented(KnownResponseError):
    """NotImplemented S3 error."""
    message = ('A header you provided implies functionality '
               'that is not implemented.')

    def __init__(self):
        super(APINotImplemented, self).__init__(self.message)


class NotSignedUp(KnownResponseError):
    """NotSignedUp S3 error."""
    message = 'Your account is not signed up.'

    def __init__(self):
        super(NotSignedUp, self).__init__(self.message)


class NoSuchBucketPolicy(KnownResponseError):
    """NoSuchBucketPolicy S3 error."""
    message = 'The specified bucket does not have a bucket policy.'

    def __init__(self):
        super(NoSuchBucketPolicy, self).__init__(self.message)


class OperationAborted(KnownResponseError):
    """OperationAborted S3 error."""
    message = ('A conflicting conditional operation is currently in '
               'progress against this resource. Try again.')

    def __init__(self):
        super(OperationAborted, self).__init__(self.message)


class PermanentRedirect(KnownResponseError):
    """PermanentRedirect S3 error."""
    message = ('The bucket you are attempting to access must be addressed '
               'using the specified endpoint. Send all future requests '
               'to this endpoint.')

    def __init__(self):
        super(PermanentRedirect, self).__init__(self.message)


class PreconditionFailed(KnownResponseError):
    """PreconditionFailed S3 error."""
    message = 'At least one of the preconditions you specified did not hold.'

    def __init__(self):
        super(PreconditionFailed, self).__init__(self.message)


class Redirect(KnownResponseError):
    """Redirect S3 error."""
    message = 'Temporary redirect.'

    def __init__(self):
        super(Redirect, self).__init__(self.message)


class RestoreAlreadyInProgress(KnownResponseError):
    """RestoreAlreadyInProgress S3 error."""
    message = 'Object restore is already in progress.'

    def __init__(self):
        super(RestoreAlreadyInProgress, self).__init__(self.message)


class RequestIsNotMultiPartContent(KnownResponseError):
    """RequestIsNotMultiPartContent S3 error."""
    message = 'Bucket POST must be of the enclosure-type multipart/form-data.'

    def __init__(self):
        super(RequestIsNotMultiPartContent, self).__init__(self.message)


class RequestTimeout(KnownResponseError):
    """RequestTimeout S3 error."""
    message = ('Your socket connection to the server was not read '
               'from or written to within the timeout period.')

    def __init__(self):
        super(RequestTimeout, self).__init__(self.message)


class RequestTimeTooSkewed(KnownResponseError):
    """RequestTimeTooSkewed S3 error."""
    message = ("The difference between the request time and the "
               "server's time is too large.")

    def __init__(self):
        super(RequestTimeTooSkewed, self).__init__(self.message)


class RequestTorrentOfBucketError(KnownResponseError):
    """RequestTorrentOfBucketError S3 error."""
    message = 'Requesting the torrent file of a bucket is not permitted.'

    def __init__(self):
        super(RequestTorrentOfBucketError, self).__init__(self.message)


class SignatureDoesNotMatch(KnownResponseError):
    """SignatureDoesNotMatch S3 error."""
    message = ('The request signature we calculated does not match the '
               'signature you provided.')

    def __init__(self):
        super(SignatureDoesNotMatch, self).__init__(self.message)


class ServiceUnavailable(KnownResponseError):
    """ServiceUnavailable S3 error."""
    message = "Service unavailable. Retry again."

    def __init__(self):
        super(ServiceUnavailable, self).__init__(self.message)


class SlowDown(KnownResponseError):
    """SlowDown S3 error."""
    message = 'Reduce your request rate.'

    def __init__(self):
        super(SlowDown, self).__init__(self.message)


class TemporaryRedirect(KnownResponseError):
    """TemporaryRedirect S3 error."""
    message = 'You are being redirected to the bucket while DNS updates.'

    def __init__(self):
        super(TemporaryRedirect, self).__init__(self.message)


class TokenRefreshRequired(KnownResponseError):
    """TokenRefreshRequired S3 error."""
    message = 'The provided token must be refreshed.'

    def __init__(self):
        super(TokenRefreshRequired, self).__init__(self.message)


class TooManyBuckets(KnownResponseError):
    """TooManyBuckets S3 error."""
    message = 'You have attempted to create more buckets than allowed.'

    def __init__(self):
        super(TooManyBuckets, self).__init__(self.message)


class UnexpectedContent(KnownResponseError):
    """UnexpectedContent S3 error."""
    message = 'This request does not support content.'

    def __init__(self):
        super(UnexpectedContent, self).__init__(self.message)


class UnresolvableGrantByEmailAddress(KnownResponseError):
    """UnresolvableGrantByEmailAddress S3 error."""
    message = ('The email address you provided does not match any account '
               'on record.')

    def __init__(self):
        super(UnresolvableGrantByEmailAddress, self).__init__(self.message)


class UserKeyMustBeSpecified(KnownResponseError):
    """UserKeyMustBeSpecified S3 error."""
    message = ('The bucket POST must contain the specified field name. '
               'If it is specified, check the order of the fields.')

    def __init__(self):
        super(UserKeyMustBeSpecified, self).__init__(self.message)


_KNOWN_ERRORS = {
    'AccessDenied': AccessDenied,
    'AccountProblem': AccountProblem,
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
    'IllegalVersioningConfigurationException':
    IllegalVersioningConfigurationException,
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
        return _KNOWN_ERRORS.get(self.code, self)

    def _handle_error_response(self, bucket_name=None):
        """
        Sets error response uses xml body if available, otherwise
        relies on HTTP headers.
        """
        if self._response.data:
            self._set_from_response_body()
        else:
            self._set_from_response_reason(bucket_name)

    def _set_from_response_body(self):
        """
        Sets all the error response fields with a valid response body.
           Raises :exc:`ValueError` if invoked on a zero length body.

        :param bucket_name: Optional bucket name resource at which error
           occurred.
        :param object_name: Option object name resource at which error
           occurred.
        """
        if not self._response.data:
            raise ValueError('response data has no body.')
        try:
            root = ElementTree.fromstring(self._response.data)
        except (ParseError, AttributeError, ValueError, TypeError) as error:
            raise InvalidXMLError('"Error" XML is not parsable. '
                                  'Message: {0}'.format(error))

        # Deal with namespaced response from sts
        tag_prefix = "{https://sts.amazonaws.com/doc/2011-06-15/}"
        if tag_prefix not in root.tag:
            tag_prefix = ""

        attr_dict = {
            tag_prefix + 'Code': 'code',
            tag_prefix + 'BucketName': 'bucket_name',
            tag_prefix + 'Key': 'object_name',
            tag_prefix + 'Message': 'message',
            tag_prefix + 'RequestId': 'request_id',
            tag_prefix + 'HostId': 'host_id'
        }
        for attribute in root.iter():
            attr = attr_dict.get(attribute.tag)
            if attr:
                setattr(self, attr, attribute.text)
        # Set amz headers.
        self._set_amz_headers()

    def _set_from_response_reason(self, bucket_name):
        """
        Sets all the error response fields from response headers.
        """
        status_dict = {
            301: lambda: ('PermanentRedirect', self._response.reason),
            307: lambda: ('Redirect', self._response.reason),
            400: lambda: ('BadRequest', self._response.reason),
            403: lambda: ('AccessDenied', self._response.reason),
            404: lambda: (
                (self.code, self.message) if not bucket_name else
                ('NoSuchKey', self._response.reason) if self.object_name else
                ('NoSuchBucket', self._response.reason)
            ),
            405: lambda: ('MethodNotAllowed', self._response.reason),
            409: lambda: ('Conflict',
                          'The bucket you tried to delete is not empty.'),
            500: lambda: ('InternalError', 'Internal Server Error.'),
            501: lambda: ('MethodNotAllowed', self._response.reason),
        }

        func = status_dict.get(self._response.status, lambda: (
            'UnknownException', self._response.reason))
        self.code, self.message = func()

        # Set amz headers.
        self._set_amz_headers()

    def _set_amz_headers(self):
        """
        Sets x-amz-* error response fields from response headers.
        """
        if self._response.headers:
            self.host_id = self._response.headers.get('x-amz-id-2',
                                                      self.host_id)
            self.request_id = self._response.headers.get('x-amz-request-id',
                                                         self.request_id)
            # 'x-amz-bucket-region' is a new undocumented field.
            self.region = self._response.headers.get('x-amz-bucket-region',
                                                     self.region)

    def __str__(self):
        return ('ResponseError: code: {0}, message: {1},'
                ' bucket_name: {2}, object_name: {3}, request_id: {4},'
                ' host_id: {5}, region: {6}').format(self.code,
                                                     self.message,
                                                     self.bucket_name,
                                                     self.object_name,
                                                     self.request_id,
                                                     self.host_id,
                                                     self.region)
