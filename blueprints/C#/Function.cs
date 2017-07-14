using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.APIGateway.Model;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Auth.AccessControlPolicy;
using Amazon.Auth.AccessControlPolicy.ActionIdentifiers;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace Auth
{
    public class Function
    {
        
        
        public Policy FunctionHandler(APIGatewayCustomAuthorizerRequest authEvent, ILambdaContext context)
        {
            
            
            try
            {
                // validate the token -- checking auth should be filled in, current function just returns true for all tokens
                var token = authEvent.AuthorizationToken;
                bool authorized = CheckAuthorization(token);
                Policy policy;
                if (authorized)
                {
                    // Create the policy statement -- this example allows s3 bucket notifications
                    // See the SDK for list of allowed Action Identifiers

                    // First, Allow Access to s3 Bucket changes 
                    var policyStatementList = new List<Statement>();
                    var s3PolicyStatement = new Statement(Statement.StatementEffect.Allow);
                    var s3ActionIdentifier = S3ActionIdentifiers.GetBucketNotification;
                    s3PolicyStatement.Actions.Add(s3ActionIdentifier);

                    // Add Principals-- This case all Users
                    s3PolicyStatement.Principals.Add(Principal.AllUsers);
                    // Specify the resource, in this case a test bucket
                    var resource = ResourceFactory.NewS3BucketResource("My-Bucket");
                    s3PolicyStatement.Resources.Add(resource);
                    policyStatementList.Add(s3PolicyStatement);
                    
                    
                    // Add conditions
                    var condition = ConditionFactory.NewSourceArnCondition("*");
                    s3PolicyStatement.Conditions.Add(condition);
                    policy = new Policy("EventListenerPolicy", policyStatementList);
                }
                else
                {
                    // Make an access denied policy
                    // First, Allow Access to s3 Bucket changes 
                    var policyStatementList = new List<Statement>();
                    var s3PolicyStatement = new Statement(Statement.StatementEffect.Deny);
                    var s3ActionIdentifier = S3ActionIdentifiers.AllS3Actions;
                    s3PolicyStatement.Actions.Add(s3ActionIdentifier);
                    
                    policy = new Policy("AccessDeniedPolicy", policyStatementList);
                }
                

                return policy;
     
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


 

}
