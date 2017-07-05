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
using Newtonsoft.Json;

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
        [LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]
        public AuthPolicy FunctionHandler(TokenAuthorizerContext input, ILambdaContext context)
        {
            try
            {
                context.Logger.LogLine($"{nameof(input.AuthorizationToken)}: {input.AuthorizationToken}");
                context.Logger.LogLine($"{nameof(input.MethodArn)}: {input.MethodArn}");

                // validate the incoming token
                // and produce the principal user identifier associated with the token

                // this could be accomplished in a number of ways:
                // 1. Call out to OAuth provider
                // 2. Decode a JWT token inline
                // 3. Lookup in a self-managed DB
                var principalId = "user|a1b2c3d4";

                // you can send a 401 Unauthorized response to the client by failing like so:
                // throw new Exception("Unauthorized");

                // if the token is valid, a policy must be generated which will allow or deny access to the client

                // if access is denied, the client will receive a 403 Access Denied response
                // if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called

                // build apiOptions for the AuthPolicy
                var methodArn = ApiGatewayArn.Parse(input.MethodArn);
                var apiOptions = new ApiOptions(methodArn.Region, methodArn.RestApiId, methodArn.Stage);

                // this function must generate a policy that is associated with the recognized principal user identifier.
                // depending on your use case, you might store policies in a DB, or generate them on the fly

                // keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
                // and will apply to subsequent calls to any method/resource in the RestApi
                // made with the same token

                // the example policy below denies access to all resources in the RestApi
                var policyBuilder = new AuthPolicyBuilder(principalId, methodArn.AwsAccountId, apiOptions);
                policyBuilder.DenyAllMethods();
                // policyBuilder.AllowMethod(HttpVerb.GET, "/users/username");

                // finally, build the policy
                var authResponse = policyBuilder.Build();

                // new! -- add additional key-value pairs
                // these are made available by APIGW like so: $context.authorizer.<key>
                // additional context is cached
                authResponse.Context.Add("key", "value"); // $context.authorizer.key -> value
                authResponse.Context.Add("number", 1);
                authResponse.Context.Add("bool", true);

                return authResponse;
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
    }
}
