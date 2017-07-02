using Newtonsoft.Json;

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
    }
}
