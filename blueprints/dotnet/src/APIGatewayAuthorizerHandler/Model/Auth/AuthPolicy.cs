using System.Collections;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace APIGatewayAuthorizerHandler.Model.Auth
{
    public class AuthPolicy
    {
        [JsonProperty(PropertyName = "principalId")]
        public string PrincipalId { get; set; }
        [JsonProperty(PropertyName = "policyDocument")]
        public PolicyDocument PolicyDocument { get; set; }
        
        [JsonProperty(PropertyName = "context", NullValueHandling = NullValueHandling.Ignore)]

        public IDictionary<string, object> Context { get; set; } = new Dictionary<string, object>();
    }
}
