using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.APIGateway.Model;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Auth.AccessControlPolicy;
using Amazon.Auth.AccessControlPolicy.ActionIdentifiers;
using Newtonsoft.Json;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace Auth
{
    public class Function
    {
        
        
        public AuthPolicy FunctionHandler(APIGatewayCustomAuthorizerRequest authEvent, ILambdaContext context)
        {
            
            
            try
            {
                // validate the token
                var token = authEvent.AuthorizationToken;
                bool authorized = CheckAuthorization(token);

                // Create the policy statement
                // This matches the policy statement example in the documentation, including the ARN
                var authPolicy = new AuthPolicy();
                authPolicy.prinicpalId = token;
                authPolicy.policyStatement = new PolicyStatement();
                authPolicy.policyStatement.Version = "2012-10-17";
                authPolicy.policyStatement.Statement = new List<States>();
                if (authorized)
                {
                    var statement = new States();
                    statement.Action = "execute-api:Invoke";
                    statement.Effect = "Allow";
                    statement.Resource = "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/";
                    authPolicy.policyStatement.Statement.Add(statement);
                }
                else
                {
                    var statement = new States();
                    statement.Action = "execute-api:Invoke";
                    statement.Effect = "Deny";
                    statement.Resource = "arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/";
                    authPolicy.policyStatement.Statement.Add(statement);
                }


                return authPolicy;
     
            }
            catch (Exception e)
            {
                Console.WriteLine("Error authorizing request. " + e.Message);
                throw;
            }
            
        }
        public virtual bool CheckAuthorization(string token)
        {
            return true;
        }
    }
    public class AuthPolicy
    {
        public string prinicpalId { get; set; }
        public PolicyStatement policyStatement { get; set; }
        public Context context { get; set; }
    }
    public class Context
    {
        public string stringKey { get; set; }
        public int numberKey { get; set; }
        public bool booleanKey { get; set; }
    }
    public class PolicyStatement
    {
        public string Version { get; set; }
        public List<States> Statement { get; set; }

    }
    public class States
    {
        public string Action { get; set; }
        public string Effect { get; set; }
        public string Resource { get; set; }
    }

 

}
