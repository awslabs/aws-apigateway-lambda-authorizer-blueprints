using Newtonsoft.Json;
using System.Collections.Generic;

namespace APIGatewayAuthorizerHandler.Model.Auth
{
    public class Statement
    {
        [JsonProperty(PropertyName = "Action")]
        public string Action { get; set; }
        [JsonProperty(PropertyName = "Effect")]
        public string Effect { get; set; } = "Deny"; // Default to Deny to ensure Allows are explicitly set
        [JsonProperty(PropertyName = "Resource")]
        public string Resource { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IDictionary<ConditionOperator, IDictionary<ConditionKey, string>> Condition { get; set; }
    }
}
