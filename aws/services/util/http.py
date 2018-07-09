import requests
from logging import Logger
from aws.services.exceptions.http_exception import GenericHttpException

from aws.services.exceptions.http_exception import GenericHttpException

class HttpUtils():

    @staticmethod
    def invokeHttpRequest(endpoint,
                          method,
                          headers,
                          body):

        if method.lower() == 'get':
            resp = requests.get(endpoint, headers=headers)
        elif method.lower() == 'post':
            resp = requests.post(endpoint, headers=headers, data=body)
        elif method.lower() == 'put':
            resp = requests.put(endpoint, data=body, headers=headers)
        elif method.lower() == 'delete':
            resp = requests.delete(endpoint, data=body, headers=headers)
        else:
            raise GenericHttpException('Only methods [get,post,put,delete] are supported')

        if resp.status_code not in ['200','201']:
            return resp.text
        else:
            raise GenericHttpException(resp.status_code, resp.text)

