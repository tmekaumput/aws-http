class GenericHttpException(Exception):
    """ An Exception class to handle generic HTTP error """
    _errorCode = -1

    def __init__(self, errorCode, description):
        """
        :type errorCode: string
        :param errorCode: HTTP error code
        :type description: string
        :param description: HTTP body content
        """
        super(self, description)
        self._errorCode = errorCode

    def getErrorCode(self):
        """

        :return: HTTP error code
        """
        return self._errorCode

    def getDescription(self):
        """

        :return: HTTP body content
        """
        return self.message