/*
* Copyright 2015-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
*
*     http://aws.amazon.com/apache2.0/
*
* or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

// Author: Caleb Petrick

using System;
using Amazon.Lambda.Core;
using APIGatewayAuthorizerHandler.Error;
using APIGatewayAuthorizerHandler.Model;
using APIGatewayAuthorizerHandler.Model.Auth;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace APIGatewayAuthorizerHandler
{
    public class Function
    {
        /// <summary>
        /// A simple function that takes the token authorizer and returns a policy based on the authentication token included.
        /// </summary>
        /// <param name="input">token authorization received by api-gateway event sources</param>
        /// <param name="context"></param>
        /// <returns>IAM Auth Policy</returns>
        public AuthPolicy FunctionHandler(TokenAuthorizerContext input, ILambdaContext context)
        {
            try
            {
                context.Logger.LogLine($"{nameof(input.AuthorizationToken)}: {input.AuthorizationToken}");
                context.Logger.LogLine($"{nameof(input.MethodArn)}: {input.MethodArn}");

                EnsureTokenIsValid(input.AuthorizationToken);
                string principleId = GetPrincipleIdFromToken(input.AuthorizationToken);

                var methodArn = ApiGatewayArn.Parse(input.MethodArn);
                string effect = GetAuthorizeEffectForResource(input.AuthorizationToken, methodArn);

                var authPolicy = new AuthPolicy(principleId, methodArn, effect)
                {
                    // Context is optional and is purely sample only
                    Context = new Context
                    {
                        StringKey = "stringval",
                        NumberKey = 123,
                        BooleanKey = true
                    }
                };

                context.Logger.LogLine("Policy Statement Applied");
                context.Logger.LogLine($"{nameof(Statement.Effect)}: {authPolicy.PolicyDocument.Statement.Effect} {nameof(Statement.Resource)}: {authPolicy.PolicyDocument.Statement.Resource}"); 
                return authPolicy;
            }
            catch (Exception ex)
            {
                if (ex is UnauthorizedException)
                    throw;

                // log the exception and return a 401
                context.Logger.LogLine(ex.ToString());
                throw new UnauthorizedException();
            }
        }

        private void EnsureTokenIsValid(string token)
        {
            // You can do logic here to validate a token
            // e.g. Verify expiration date or hash integrity.

            // For this demo, there are only two valid tokens; "allow" and "deny" (deny results in 403 forbidden)
            if (!token.Equals("allow", StringComparison.OrdinalIgnoreCase) && !token.Equals("deny", StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedException(); // return a 401 Unauthorized to the client.
            }
        }

        private string GetPrincipleIdFromToken(string token)
        {
            // For this demo we will return a random guid
            // Do some logic here to extract or generate your principle id.
            return Guid.NewGuid().ToString();
        }

        private string GetAuthorizeEffectForResource(string inputAuthorizationToken, ApiGatewayArn methodArn)
        {
            // Do some logic to verifiy if the token has access the Rest API Resources
            // For this demo, only tokens equal to "allow" can access resources.
            return inputAuthorizationToken.Equals("allow", StringComparison.OrdinalIgnoreCase) ? "Allow" : "Deny";
        }
    }
}
