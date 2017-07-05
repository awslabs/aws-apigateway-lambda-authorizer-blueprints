using System.Linq;
using Amazon.Lambda.TestUtilities;
using APIGatewayAuthorizerHandler.Model;
using Newtonsoft.Json;
using Xunit;

namespace APIGatewayAuthorizerHandler.Tests
{
    public class IntegrationTests
    {
        [Fact]
        public void CallingFunctionWithAnyTokenReturnDenyAllPolicy()
        {
            var function = new Function();
            var request = SampleRequest();
            var lambdaContext = new TestLambdaContext();
            var result = function.FunctionHandler(request, lambdaContext);

            Assert.Equal(result.PrincipalId, "user|a1b2c3d4");
            var firstStatement = result.PolicyDocument.Statement.First();
            Assert.Equal("Deny", firstStatement.Effect);
            Assert.Equal("arn:aws:execute-api:ap-southeast-2:123123123123:123sdfasdf12/prod/*/*", firstStatement.Resource);
        }

        private static TokenAuthorizerContext SampleRequest(string type = "TOKEN", 
            string token = "Allow",
            string region = "ap-southeast-2",
            string accoundId = "123123123123",
            string restApiId = "123sdfasdf12",
            string stage = "prod",
            string verb = "GET")
        {
            string json = $@"{{ ""Type"": ""{type}"", ""AuthorizationToken"": ""{token}"", ""MethodArn"": ""arn:aws:execute-api:{region}:{accoundId}:{restApiId}/{stage}/{verb}/"" }}";
            return JsonConvert.DeserializeObject<TokenAuthorizerContext>(json);
        }
    }
}
