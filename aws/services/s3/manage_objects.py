from aws.services.v4.auth import AWS4SignerBase, AWS4SignerForAuthorizationHeader
import binascii


from aws.services.util.http import HttpUtils

class ObjectManager:
    """
    Collection of S3 operations for S3 object management
    """

    _awsAccessKey = None
    _awsSecretKey = None
    _bucketName = None
    _regionName = None

    _objectContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc tortor metus, sagittis eget augue ut,\n" \
            + "feugiat vehicula risus. Integer tortor mauris, vehicula nec mollis et, consectetur eget tortor. In ut\n" \
            + "elit sagittis, ultrices est ut, iaculis turpis. In hac habitasse platea dictumst. Donec laoreet tellus\n" \
            + "at auctor tempus. Praesent nec diam sed urna sollicitudin vehicula eget id est. Vivamus sed laoreet\n" \
            + "lectus. Aliquam convallis condimentum risus, vitae porta justo venenatis vitae. Phasellus vitae nunc\n" \
            + "varius, volutpat quam nec, mollis urna. Donec tempus, nisi vitae gravida facilisis, sapien sem malesuada\n" \
            + "purus, id semper libero ipsum condimentum nulla. Suspendisse vel mi leo. Morbi pellentesque placerat congue.\n" \
            + "Nunc sollicitudin nunc diam, nec hendrerit dui commodo sed. Duis dapibus commodo elit, id commodo erat\n" \
            + "congue id. Aliquam erat volutpat.\n"

    def __init__(self,
                 awsAccessKey,
                 awsSecretKey,
                 bucketName,
                 regionName):
        """

        :param awsAccessKey: AWS Access Key
        :param awsSecretKey: AWS Secret Key
        :param bucketName: S3 Bucket Name
        :param regionName: S3 Region Name
        """

        self._awsAccessKey = awsAccessKey
        self._awsSecretKey = awsSecretKey
        self._bucketName = bucketName
        self._regionName = regionName

    def pubS3Object(self):

        """
        Generate authorisation header and signed message then upload file to S3 storage

        :return: Returns response body content from S3 API
        """

        if self._regionName == "us-east-1":
            endpoint = "https://s3.amazonaws.com/" + self._bucketName + "/ExampleObject.txt"
        else:
            endpoint = "https://s3-" + self._regionName + ".amazonaws.com/" + self._bucketName + "/ExampleObject.txt"

        hashedBinaryContent = AWS4SignerBase.hash(bytearray(self._objectContent,"utf-8"))
        hashedHexContent = binascii.hexlify(hashedBinaryContent)
        headers = {
                    "x-amz-content-sha256": hashedHexContent,
                    "content-length": str(len(self._objectContent)),
                    "x-amz-storage-class": "REDUCED_REDUNDANCY"
                    }

        signer = AWS4SignerForAuthorizationHeader(endpoint, "PUT", "s3", self._regionName)
        authorization = signer.computeSignature(headers,
                                                None, # no query parameters
                                                hashedHexContent,
                                                self._awsAccessKey,
                                                self._awsSecretKey)

        headers['Authorization'] = authorization

        resp = HttpUtils.invokeHttpRequest(endpoint=endpoint,
                          method='PUT',
                          headers=headers,
                          body=self._objectContent)
        return resp


