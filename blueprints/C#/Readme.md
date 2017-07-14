# AWS Lambda Custom Authorization Template

This services as boilerplate code for a API Gateway custom authorization Lambda function.

It authorizes *any* token, granting S3 notifications to a dummy bucket. This code is merely acts as a sample for API gateway custom authorization, and should not be utilized in production as it allows any token. An authorization method should be incorporated before deployment. 

This blueprint makes use of the AWS SDK for .NET. This allows for the simple creation of a Policy, as the SDK provides useful functions to easily create this policy.

