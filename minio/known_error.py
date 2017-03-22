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
    message = '	The email address you provided is associated with ' \
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

class CrecentialNotSupported(KnownResponseError):
    message = '	This request does not support credentials.'

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
    message = '	You did not provide the number of bytes specified by the ' \
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
    message = '	The list of parts was not in ascending order.Parts list ' \
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

class NotImplemented(KnownResponseError):
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
    'CrecentialNotSupported': CrecentialNotSupported,
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
    'NotImplemented': NotImplemented,
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
