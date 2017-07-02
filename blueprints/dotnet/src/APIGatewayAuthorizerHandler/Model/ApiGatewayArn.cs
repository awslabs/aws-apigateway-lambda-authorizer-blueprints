using System.Linq;

namespace APIGatewayAuthorizerHandler.Model
{
    /// <summary>
    /// POCO to simplify working with the MethodArn format.
    /// </summary>
    public class ApiGatewayArn
    {
        public string Arn { get; set; } = "arn";
        public string Aws { get; set; } = "aws";
        public string ApiGateway { get; set; } = "execute-api";
        public string Region { get; set; }
        public string AwsAccountId { get; set; }
        public string RestApiId { get; set; }
        public string Stage { get; set; }
        public string Method { get; set; }
        public string Resource { get; set; }

        public override string ToString()
        {
            string resourceSuffix = Resource == null ? string.Empty : $"/{Resource}"; // if theres no resource we don't want to end up with an extra "/"
            return $"{Arn}:{Aws}:{ApiGateway}:{Region}:{AwsAccountId}:{RestApiId}/{Stage}/{Method}{resourceSuffix}";
        }

        public static ApiGatewayArn Parse(string value)
        {
            var result = new ApiGatewayArn();
            string[] arnSplit = value.Split(':');

            result.Arn = arnSplit[0];
            result.Aws = arnSplit[1];
            result.ApiGateway = arnSplit[2];

            result.Region = arnSplit[3];
            result.AwsAccountId = arnSplit[4];
            
            string[] pathSplit = arnSplit[5].Split('/');
            result.RestApiId = pathSplit[0];
            result.Stage = pathSplit[1];
            result.Method = pathSplit[2];
            
            if (pathSplit.Length > 3)
            {
                result.Resource = string.Join("/", pathSplit.Skip(3));
            }

            return result;
        }

        public static bool TryParse(string value, out ApiGatewayArn methodArn)
        {
            try
            {
                methodArn = Parse(value);
                return true;
            }
            catch
            {
                methodArn = null;
                return false;
            }
        }
    }
}
