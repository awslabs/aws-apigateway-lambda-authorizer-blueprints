using System.Linq;

namespace APIGatewayAuthorizerHandler.Model
{
    /// <summary>
    /// Provided a POCO to simplify working with the MethodArn format.
    /// </summary>
    public class ApiGatewayArn
    {
        public string Partition { get; set; } = "aws";
        public string Service { get; set; } = "execute-api";
        public string Region { get; set; }
        public string AwsAccountId { get; set; }
        public string RestApiId { get; set; }
        public string Stage { get; set; }
        public string Verb { get; set; }
        public string Resource { get; set; }

        public override string ToString()
        {
            return $"arn:{Partition}:{Service}:{Region}:{AwsAccountId}:{RestApiId}/{Stage}/{Verb}/{Resource}";
        }

        public static ApiGatewayArn Parse(string value)
        {
            var result = new ApiGatewayArn();
            string[] arnSplit = value.Split(':');
            
            result.Partition = arnSplit[1];
            result.Service = arnSplit[2];

            result.Region = arnSplit[3];
            result.AwsAccountId = arnSplit[4];
            
            string[] pathSplit = arnSplit[5].Split('/');
            result.RestApiId = pathSplit[0];
            result.Stage = pathSplit[1];
            result.Verb = pathSplit[2];
            
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
