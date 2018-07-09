from datetime import datetime, timedelta
import pytz
import re
import urllib
import urlparse
import hashlib
import hmac
import binascii
from pytz import timezone



class _SIGNNER_CONST:
    @staticmethod
    def EMPTY_BODY_SHA256():
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    @staticmethod
    def UNSIGNED_PAYLOAD():
        return "UNSIGNED-PAYLOAD"

    @staticmethod
    def SCHEME():
        return "AWS4"

    @staticmethod
    def ALGORITHM():
        return "HMAC-SHA256"

    @staticmethod
    def TERMINATOR():
        return "aws4_request"

    @staticmethod
    def ISO8601BasicFormat():
        return "%Y%m%dT%H%M%SZ"

    @staticmethod
    def DateStringFormat():
        return "%Y%m%d"

SIGNER_CONST = _SIGNNER_CONST()

"""
This is the module for AWS4 authorisation classes
"""

class AWS4SignerBase(object):
    """
    Common methods and properties for all AWS4 signer variants
    """

    _dateTimeFormat = None
    _dateStampFormat = None
    _dateTimeFormatZone = None
    _dateStampFormatZone = None

    _endpoint = None
    _method = None
    _serviceName = None
    _regionName = None

    def __init__(self,
                 endpoint,
                 method,
                 serviceName,
                 regionName):
        """
        Create a new AWS V4 signer.
        :param endpointUri: The service endpoint, including the path to any resource.
        :param httpMethod: The HTTP verb for the request, e.g. GET.
        :param serviceName: The signing name of the service, e.g. 's3'.
        :param regionName: The system name of the AWS region associated with the endpoint, e.g. us-east-1.
        """

        self._dateTimeFormat = SIGNER_CONST.ISO8601BasicFormat()
        self._dateStampFormat = SIGNER_CONST.DateStringFormat()
        self._dateTimeFormatZone = pytz.utc
        self._dateStampFormatZone = pytz.utc

        self._endpoint = endpoint
        self._method = method
        self._serviceName = serviceName
        self._regionName = regionName



    @staticmethod
    def getCanonicalizeHeaderNames(headers):

        """

        :type headers: dict
        :param headers:
        :return: the canonical collection of header names that will be included in the signature. For AWS4, all header names must be included in the process in sorted canonicalized order.
        """

        headerKeys = sorted(headers.keys(), key=lambda s: s.lower())
        buffer = ""
        for headerKey in headerKeys:
            if (len(buffer) > 0):
                buffer += ";"
            buffer += headerKey.lower()

        return buffer

    @staticmethod
    def getCanonicalizedHeaderString(headers):
        """

        :type headers: dict
        :param headers: HTTP Headers
        :return: Computes the canonical headers with values for the request. For AWS4, all headers must be included in the signing process.
        """
        if (headers is None or len(headers.keys()) == 0):
            return ""

        headerKeys = sorted(headers.keys(), key=lambda s: s.lower())

        pattern = re.compile(r"\\s+")

        hdrBuffer = ""
        for headerKey in headerKeys:
            hdrBuffer += pattern.sub(" ", headerKey.lower()) + ":" + pattern.sub(" ", headers[headerKey])
            hdrBuffer += "\n"

        return hdrBuffer

    @staticmethod
    def getCanonicalRequest(endpoint,
                            httpMethod,
                            queryParameters,
                            canonicalizedHeaderNames,
                            canonicalizedHeaders,
                            bodyHash):
        """

        :param endpoint:
        :param httpMethod:
        :param queryParameters:
        :param canonicalizedHeaderNames:
        :param canonicalizedHeaders:
        :param bodyHash:
        :return: the canonical request string to go into the signer process. This consists of several canonical sub-parts.
        """
        return httpMethod + "\n" + \
                        AWS4SignerBase.getCanonicalizedResourcePath(endpoint) + "\n" + \
                        queryParameters + "\n" + \
                        canonicalizedHeaders + "\n" + \
                        canonicalizedHeaderNames + "\n" + \
                        bodyHash


    @staticmethod
    def getCanonicalizedResourcePath(endpoint):
        """
        :param endpoint:
        :return: Returns the canonicalized resource path for the service endpoint.
        """
        if not endpoint:
            return "/"

        parsedURL = urlparse.urlparse(endpoint)
        print parsedURL
        encodedString = urllib.quote(parsedURL.path, safe='/:?=&')

        if encodedString.startswith("/"):
            return encodedString
        else:
            return "/" + encodedString


    @staticmethod
    def getCanonicalizedQueryString(parameters):

        """
        Examines the specified query string parameters and returns a canonicalized form.

        The canonicalized query string is formed by first sorting all the query
        string parameters, then URI encoding both the key and value and then
        joining them, in order, separating key value pairs with an '&'.

        :param parameters: The query string parameters to be canonicalized.
        :return: A canonicalized form for the specified query string parameters.
        """
        if not parameters:
            return ""

        parameterKeys = sorted(parameters.keys(), key=lambda s: urllib.urlencode(s))

        buffer = ""
        for parameterKey in parameterKeys:
            buffer += urllib.urlencode(parameterKey) + "=" + urllib.urlencode(parameters[parameterKey])

        if buffer:
            buffer = buffer[:-1]

        return buffer

    @staticmethod
    def getStringToSign(scheme,
                        algorithm,
                        dateTime,
                        scope,
                        canonicalRequest):
        """
        :param scheme:
        :param algorithm:
        :param dateTime:
        :param scope:
        :param canonicalRequest:
        :return: Concatenation of parameters with line breaks
        """
        return scheme + "-" + algorithm + "\n" + \
                dateTime + "\n" + \
                scope + "\n" + \
                hashlib.sha256(canonicalRequest).hexdigest()

    @staticmethod
    def hash(data):
        """
        Compute hash value of the input parameter

        :param data:
        :return:
        """
        h = hashlib.sha256()
        h.update(data)
        return h.digest()

    @staticmethod
    def sign(data,
             key,
             algorithm):
        dataBytes = bytearray(data, 'utf-8')

        if algorithm in ['sha256','SHA256']:
            h = hmac.new(key=key, msg=dataBytes, digestmod=hashlib.sha256)
        else:
            raise Exception('Algorithm [' + algorithm + '] not supported')

        return h.digest()


class AWS4SignerForAuthorizationHeader(AWS4SignerBase):
    """
    An AWS4 Signer class to compute authorisation header
    """

    def __init__(self,
                 endpoint,
                 method,
                 serviceName,
                 regionName):
        """
        :param endpoint:
        :param method:
        :param serviceName:
        :param regionName:
        """
        super(AWS4SignerForAuthorizationHeader, self).__init__(endpoint, method, serviceName, regionName)



    def computeSignature(self,
                         headers,
                         queryParameters,
                         bodyHash,
                         awsAccessKey,
                         awsSecretKey):

        """
        Computes an AWS4 signature for a request, ready for inclusion as an 'Authorization' header.

        :param headers: The request headers; 'Host' and 'X-Amz-Date' will be added to this set.
        :param queryParameters: Any query parameters that will be added to the endpoint. The parameters should be specified in canonical format.
        :param bodyHash: Precomputed SHA256 hash of the request body content; this value should also be set as the header 'X-Amz-Content-SHA256' for non-streaming uploads.
        :param awsAccessKey: The user's AWS Access Key.
        :param awsSecretKey: The user's AWS Secret Key.
        :return: The computed authorization string for the request. This value needs to be set as the header 'Authorization' on the subsequent HTTP request.
        """

        currentTime = datetime.now(tz=timezone('Australia/NSW'))

        # There seems to be a bug as the timestamp is always 5 minutes behind when converted to UTC
        currentTime = currentTime + timedelta(minutes=5)

        # Convert timestamp to UTC
        dateTimeStamp = currentTime.astimezone(self._dateTimeFormatZone).strftime(self._dateTimeFormat)

        headers['x-amz-date'] = dateTimeStamp

        parsedURL = urlparse.urlparse(self._endpoint)
        host = parsedURL.hostname
        if parsedURL.port:
            host += ":" + str(parsedURL.port)

        headers['Host'] = host

        canonicalizedHeaderNames = self.getCanonicalizeHeaderNames(headers)
        canonicalizedHeaders = self.getCanonicalizedHeaderString(headers)

        canonicalizedQueryParameters = self.getCanonicalizedQueryString(queryParameters)
        canonicalRequest = self.getCanonicalRequest(endpoint=self._endpoint,
                                                    httpMethod=self._method,
                                                    queryParameters=canonicalizedQueryParameters,
                                                    canonicalizedHeaderNames=canonicalizedHeaderNames,
                                                    canonicalizedHeaders=canonicalizedHeaders,
                                                    bodyHash=bodyHash)

        print '##################################'
        print canonicalRequest
        print '##################################'

        dateStamp = currentTime.strftime(self._dateStampFormat)

        scope = dateStamp + "/" + self._regionName + "/" + self._serviceName + "/" + SIGNER_CONST.TERMINATOR()
        stringToSign = self.getStringToSign(SIGNER_CONST.SCHEME(), SIGNER_CONST.ALGORITHM(), dateTimeStamp, scope, canonicalRequest)

        print '##################################'
        print stringToSign
        print '##################################'

        kSecret = bytearray(SIGNER_CONST.SCHEME() + awsSecretKey, 'utf-8')
        kDate = self.sign(dateStamp, kSecret, "SHA256")
        kRegion = self.sign(self._regionName, kDate, "SHA256")
        kService = self.sign(self._serviceName, kRegion, "SHA256")
        kSigning = self.sign(SIGNER_CONST.TERMINATOR(), kService, "SHA256")
        signature = self.sign(stringToSign, kSigning, "SHA256")

        credentialsAuthorizationHeader = "Credential=" + awsAccessKey + "/" + scope
        signedHeadersAuthorizationHeader = "SignedHeaders=" + canonicalizedHeaderNames
        signatureAuthorizationHeader = "Signature=" + binascii.hexlify(signature)

        authorizationHeader = SIGNER_CONST.SCHEME() + "-" + SIGNER_CONST.ALGORITHM() + " " \
                            + credentialsAuthorizationHeader + ", " \
                            + signedHeadersAuthorizationHeader + ", " \
                            + signatureAuthorizationHeader

        return authorizationHeader