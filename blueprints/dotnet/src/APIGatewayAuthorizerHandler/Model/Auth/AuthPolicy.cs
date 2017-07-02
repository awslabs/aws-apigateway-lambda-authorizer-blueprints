using Newtonsoft.Json;

namespace APIGatewayAuthorizerHandler.Model.Auth
{
    public class AuthPolicy
    {
        [JsonProperty(PropertyName = "principalId")]
        public string PrincipalId { get; set; }
        [JsonProperty(PropertyName = "policyDocument")]
        public PolicyDocument PolicyDocument { get; set; }
        
        [JsonProperty(PropertyName = "context")]
        public Context Context { get; set; } // Context is optional

        public AuthPolicy()
        {
        }

        /// <summary>
        /// Construct a basic Policy to Allow or Deny all resources for the rest api.
        /// </summary>
        public AuthPolicy(string principleId, ApiGatewayArn methodArn, string effect)
        {
            var resourceArn = new ApiGatewayArn
            {
                Region = methodArn.Region ?? "*",
                AwsAccountId = methodArn.AwsAccountId,
                RestApiId = methodArn.RestApiId ?? "*",
                Stage = methodArn.Stage ?? "*",
                Method = "*", // In this demo we are allowing all methods, This should however reflect the principles access.
                Resource = methodArn.Resource
            };
            
            PrincipalId = principleId;
            PolicyDocument = new PolicyDocument
            {
                Statement = new Statement
                {
                    Action = "execute-api:Invoke",
                    Effect = effect,
                    Resource = resourceArn.ToString()
                }
            };
        }
    }
}
