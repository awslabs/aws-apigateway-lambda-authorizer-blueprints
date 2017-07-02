using Newtonsoft.Json;

namespace APIGatewayAuthorizerHandler.Model
{
    public class TokenAuthorizerContext
    {
        [JsonProperty(PropertyName = "Type")]
        public string Type { get; set; }
        [JsonProperty(PropertyName = "AuthorizationToken")]
        public string AuthorizationToken { get; set; }
        [JsonProperty(PropertyName = "MethodArn")]
        public string MethodArn { get; set; }
    }
}
