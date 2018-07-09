# Signature Version 4 Signing Process

Signature Version 4 is the process to add authentication information to AWS requests. For security, most requests to AWS must be signed with an access key, which consists of an access key ID and secret access key.

    Important

        When you use the AWS Command Line Interface (AWS CLI) or one of the AWS SDKs to make requests to AWS, 
        these tools automatically sign the requests for you with the access key that you specify when you configure the tools. 
        When you use these tools, you don't need to learn how to sign requests yourself. 
        However, when you manually create HTTP requests to AWS, you must sign the requests yourself.

## How Signature Version 4 works

1. You create a canonical request.

2. You use the canonical request and some other information to create a string to sign.

3. You use your AWS secret access key to derive a signing key, and then use that signing key and the string to sign to create a signature.

4. You add the resulting signature to the HTTP request in a header or as a query string parameter.

When AWS receives the request, it performs the same steps that you did to calculate the signature. AWS then compares the calculated signature to the one you sent with the request. If the signatures match, the request is processed. If the signatures don't match, the request is denied.

For more information, see the following resources:

- To get started with the signing process, see Signing AWS Requests with Signature Version 4.

- For sample signed requests, see Examples of the Complete Version 4 Signing Process (Python).

- If you have questions about Signature Version 4, post your question in the AWS Identity and Access Management forum.

## Summary
The project has followed the guidline published by Amazon Web Services together with abstract design layer aiming to modularise the API interfaces

Packages are classified into authorisation and management classes such as S3, EC2, etc. that will allow consume to perform operatsion with no need to deal with low level API layer.

