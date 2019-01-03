namespace APIGatewayAuthorizerHandler.Model.Auth
{
    public class ConditionKey
    {
        private readonly string _key;

        public ConditionKey(string key)
        {
            _key = key;
        }

        public override string ToString()
        {
            return _key;
        }

        public static ConditionKey CurrentTime => new ConditionKey("aws:CurrentTime");
        public static ConditionKey EpochTime => new ConditionKey("aws:EpochTime");
        public static ConditionKey MultiFactorAuthAge => new ConditionKey("aws:MultiFactorAuthAge");
        public static ConditionKey MultiFactorAuthPresent => new ConditionKey("aws:MultiFactorAuthPresent");
        public static ConditionKey Referer => new ConditionKey("aws:Referer");
        public static ConditionKey SecureTransport => new ConditionKey("aws:SecureTransport");
        public static ConditionKey SourceArn => new ConditionKey("aws:SourceArn");
        public static ConditionKey SourceIp => new ConditionKey("aws:SourceIp");
        public static ConditionKey TokenIssueTime => new ConditionKey("aws:TokenIssueTime");
        public static ConditionKey UserAgent => new ConditionKey("aws:UserAgent");
        public static ConditionKey PrincipalType => new ConditionKey("aws:PrincipalType");
        public static ConditionKey SourceVpc => new ConditionKey("aws:SourceVpc");
        public static ConditionKey SourceVpce => new ConditionKey("aws:SourceVpce");
        public static ConditionKey Userid => new ConditionKey("aws:userid");
        public static ConditionKey Username => new ConditionKey("aws:username");
    }
}
