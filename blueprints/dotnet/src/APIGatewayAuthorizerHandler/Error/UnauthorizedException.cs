namespace APIGatewayAuthorizerHandler.Error
{
    internal class UnauthorizedException : System.Exception
    {
        internal UnauthorizedException() : base("Unauthorized")
        {
        }
    }
}
