# Amazon API Gateway - Custom Authorizer Blueprints for AWS Lambda
We've added blueprints and examples in 3 languages for Lambda-based custom Authorizers for use in API Gateway.

## Java
Not available in the Lambda console. Use the AuthPolicy object to generate and serialize IAM policies for your custom authorizer. See javadoc comments for more details.

## NodeJS
Also available in the Lambda console, the NodeJS blueprint makes it easy to generate IAM policies, including Conditions.

## Python
Also available in the Lambda console, the Python blueprint includes the AuthPolicy class, which makes generating IAM policies simple and easy to understand.

## Go
Not available in the Lambda console. Based on the [JavaScript sample](https://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html#api-gateway-custom-authorizer-token-lambda-function-create) from the API Gateway documentation,
this blueprint showcases the [aws-lambda-go](https://github.com/aws/aws-lambda-go) library

## Docs ##
For more details, see public documentation for:
- API Gateway Custom Authorizers -- [Blog Post](https://aws.amazon.com/blogs/compute/introducing-custom-authorizers-in-amazon-api-gateway/) -- [Developer Guide](http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html)
- IAM Policy Language -- [API Gateway Developer Guide](http://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html) -- [Policy Language Reference](http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html)
