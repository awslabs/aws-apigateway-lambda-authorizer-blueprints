#![allow(dead_code)]
#[macro_use]
extern crate lambda_runtime as lambda;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate simple_logger;

use lambda::error::HandlerError;

use serde_json::json;
use std::error::Error;

static POLICY_VERSION: &str = "2012-10-17"; // override if necessary

fn my_handler(
    event: APIGatewayCustomAuthorizerRequest,
    _ctx: lambda::Context,
) -> Result<APIGatewayCustomAuthorizerResponse, HandlerError> {
    info!("Client token: {}", event.authorization_token);
    info!("Method ARN: {}", event.method_arn);

    // validate the incoming token
    // and produce the principal user identifier associated with the token

    // this could be accomplished in a number of ways:
    // 1. Call out to OAuth provider
    // 2. Decode a JWT token inline
    // 3. Lookup in a self-managed DB
    let principal_id = "user|a1b2c3d4";

    // you can send a 401 Unauthorized response to the client by failing like so:
    // Err(HandlerError{ msg: "Unauthorized".to_string(), backtrace: None });

    // if the token is valid, a policy must be generated which will allow or deny access to the client

    // if access is denied, the client will recieve a 403 Access Denied response
    // if access is allowed, API Gateway will proceed with the backend integration configured on the method that was called

    // this function must generate a policy that is associated with the recognized principal user identifier.
    // depending on your use case, you might store policies in a DB, or generate them on the fly

    // keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
    // and will apply to subsequent calls to any method/resource in the RestApi
    // made with the same token

    //the example policy below denies access to all resources in the RestApi
    let tmp: Vec<&str> = event.method_arn.split(":").collect();
    let api_gateway_arn_tmp: Vec<&str> = tmp[5].split("/").collect();
    let aws_account_id = tmp[4];
    let region = tmp[3];
    let rest_api_id = api_gateway_arn_tmp[0];
    let stage = api_gateway_arn_tmp[1];

    let policy = APIGatewayPolicyBuilder::new(region, aws_account_id, rest_api_id, stage)
        .deny_all_methods()
        .build();

    // new! -- add additional key-value pairs associated with the authenticated principal
    // these are made available by APIGW like so: $context.authorizer.<key>
    // additional context is cached
    Ok(APIGatewayCustomAuthorizerResponse {
        principal_id: principal_id.to_string(),
        policy_document: policy,
        context: json!({
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true
        }),
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(my_handler);

    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIGatewayCustomAuthorizerRequest {
    #[serde(rename = "type")]
    _type: String,
    authorization_token: String,
    method_arn: String,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct APIGatewayCustomAuthorizerPolicy {
    Version: String,
    Statement: Vec<IAMPolicyStatement>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct APIGatewayCustomAuthorizerResponse {
    principal_id: String,
    policy_document: APIGatewayCustomAuthorizerPolicy,
    context: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
struct IAMPolicyStatement {
    Action: Vec<String>,
    Effect: Effect,
    Resource: Vec<String>,
}

struct APIGatewayPolicyBuilder {
    region: String,
    aws_account_id: String,
    rest_api_id: String,
    stage: String,
    policy: APIGatewayCustomAuthorizerPolicy,
}

#[derive(Serialize, Deserialize)]
enum Method {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "*PUT")]
    Put,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "HEAD")]
    Head,
    #[serde(rename = "OPTIONS")]
    Options,
    #[serde(rename = "*")]
    All,
}

#[derive(Serialize, Deserialize)]
enum Effect {
    Allow,
    Deny,
}

impl APIGatewayPolicyBuilder {
    pub fn new(
        region: &str,
        account_id: &str,
        api_id: &str,
        stage: &str,
    ) -> APIGatewayPolicyBuilder {
        Self {
            region: region.to_string(),
            aws_account_id: account_id.to_string(),
            rest_api_id: api_id.to_string(),
            stage: stage.to_string(),
            policy: APIGatewayCustomAuthorizerPolicy {
                Version: POLICY_VERSION.to_string(),
                Statement: vec![],
            },
        }
    }

    pub fn add_method<T: Into<String>>(
        mut self,
        effect: Effect,
        method: Method,
        resource: T,
    ) -> Self {
        let resource_arn = format!(
            "arn:aws:execute-api:{}:{}:{}/{}/{}/{}",
            &self.region,
            &self.aws_account_id,
            &self.rest_api_id,
            &self.stage,
            serde_json::to_string(&method).unwrap(),
            resource.into().trim_start_matches("/")
        );

        let stmt = IAMPolicyStatement {
            Effect: effect,
            Action: vec!["execute-api:Invoke".to_string()],
            Resource: vec![resource_arn],
        };

        self.policy.Statement.push(stmt);
        self
    }

    pub fn allow_all_methods(self) -> Self {
        self.add_method(Effect::Allow, Method::All, "*")
    }

    pub fn deny_all_methods(self) -> Self {
        self.add_method(Effect::Deny, Method::All, "*")
    }

    pub fn allow_method(self, method: Method, resource: String) -> Self {
        self.add_method(Effect::Allow, method, resource)
    }

    pub fn deny_method(self, method: Method, resource: String) -> Self {
        self.add_method(Effect::Deny, method, resource)
    }

    // Creates and executes a new child thread.
    pub fn build(self) -> APIGatewayCustomAuthorizerPolicy {
        self.policy
    }
}
