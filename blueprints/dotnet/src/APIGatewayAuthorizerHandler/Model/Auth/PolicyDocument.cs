using Newtonsoft.Json;

namespace APIGatewayAuthorizerHandler.Model.Auth
{
    public class PolicyDocument
    {
        [JsonProperty(PropertyName = "Version")]
        public string Version { get; set; } = "2012-10-17";
        [JsonProperty(PropertyName = "Statement")]
        public Statement Statement { get; set; }
    }
}
