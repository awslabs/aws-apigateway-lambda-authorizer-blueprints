using Newtonsoft.Json;

namespace APIGatewayAuthorizerHandler.Model.Auth
{
    public class Context
    {
        [JsonProperty(PropertyName = "stringKey")]
        public string StringKey { get; set; }
        [JsonProperty(PropertyName = "numberKey")]
        public int NumberKey { get; set; }
        [JsonProperty(PropertyName = "booleanKey")]
        public bool BooleanKey { get; set; }
    }
}
