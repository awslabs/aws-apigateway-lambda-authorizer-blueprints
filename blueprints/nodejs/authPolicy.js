/*
* Copyright 2015-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
*
*     http://aws.amazon.com/apache2.0/
*
* or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

exports.handler = function(event, context, callback) {

  // Validate the incoming token (available on event.authorizationToken for V1 payload or event.authorization for V2 payload) 
  // and produce the principal user identifier associated with the token.
  // This could be accomplished in a number of ways:
  // 1. Call out to OAuth provider
  // 2. Decode a JWT token inline
  // 3. Lookup in a self-managed DB
  const principalId = 'user|a1b2c3d4'

  // You can send a 401 Unauthorized response to the client by failing like so:
  // callback("Unauthorized", null);

  // If the token is valid, a policy must be generated which will allow or deny access to the client.
  // If access is denied, the client will receive a 403 Access Denied response.
  // If access is allowed, API Gateway will proceed with the backend integration configured on the method that was called.

  // This function must generate a policy that is associated with the recognized principal user identifier.
  // Depending on your use case, you might store policies in a DB, or generate them on the fly.

  // Keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
  // and will apply to subsequent calls to any method/resource in the RestApi made with the same token.

  // The example policy below denies access to all resources in the RestApi and adds additional context
  // available by APIGW like so: $context.authorizer.<key> . This context is cached.
  const authPolicy = authPolicyFromEvent(event, principalId)
    .denyAllMethods()
    .withContext({
      key : 'value', // $context.authorizer.key -> value
      number : 1,
      bool: true
    })
    .build();

  callback(null, authPolicy);
};

const Payload = {
  VERSION_1: '1.0',
  VERSION_2: '2.0'
};

const ALL_RESOURCES = '*';

/**
 * A set of existing HTTP verbs supported by API Gateway. This property is here
 * only to avoid spelling mistakes in the policy.
 *
 * @property HttpVerb
 * @type {Object}
 */
const HttpVerb = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  PATCH: 'PATCH',
  HEAD: 'HEAD',
  DELETE: 'DELETE',
  OPTIONS: 'OPTIONS',
  ALL: ALL_RESOURCES
};

const Effect = {
  ALLOW: 'Allow',
  DENY: 'Deny'
};

const Action = {
  EXECUTE_API: 'execute-api:Invoke'
};

const authPolicyFromEvent = function(event, principalId) {

  // Arn format: 'arn:aws:execute-api:eu-west-1:123456789102:vjpmhhtdi6/dev/GET/test'
  const extractInfosFromArn = arn => {

    const parts = arn.split(':');

    if (parts.length < 6) {
      throw new Error('Invalid arn format');
    }

    const regionPart = parts[3];
    const awsAccountIdPart = parts[4];
    const apiGatewayArnParts = parts[5].split('/');
    const apiGatewayRestApiIdPart = apiGatewayArnParts[0];
    const apiGatewayStagePart = apiGatewayArnParts[1];

    return {
      region: regionPart,
      awsAccountId: awsAccountIdPart,
      apiGateway: {
        restApiId: apiGatewayRestApiIdPart,
        stage: apiGatewayStagePart
      }
    };
  }

  const arn = event.version === Payload.VERSION_1
    ? event.methodArn
    : event.routeArn;

  if (!arn) {
    throw new Error('Arn not found. Check your event format.');
  }

  const infos = extractInfosFromArn(arn);

  return authPolicy(principalId, infos.awsAccountId, {
    region: infos.region,
    restApiId: infos.apiGateway.restApiId,
    stage: infos.apiGateway.stage
  });
};

const authPolicy = function(_principalId, _awsAccountId, apiOptions) {

  const policyVersion = '2012-10-17';
  const pathRegex = /^[/.a-zA-Z0-9-*]+$/;

  const principalId = _principalId;
  const awsAccountId = _awsAccountId;
  const restApiId = apiOptions.restApiId || ALL_RESOURCES;
  const region = apiOptions.region || ALL_RESOURCES;
  const stage = apiOptions.stage || ALL_RESOURCES;

  const allowedMethods = [];
  const deniedMethods = [];

  const customStatements = [];

  let context = {};

  const formatResource = resource => {

    if (resource.startsWith('/')) {
      return resource.substring(1, resource.length);
    }

    return resource;
  };

  const addMethod = (effect, verb, resource, conditions) => {

    if (!HttpVerb[verb] && verb !== ALL_RESOURCES) {
      throw new Error(`Invalid HTTP verb ${verb}. Allowed verbs in HttpVerb enum.`);
    }

    const decodedResource = decodeURI(resource);
    if (!pathRegex.test(decodedResource)) {
      throw new Error(`Invalid resource path: ${decodedResource}. Path should match ${pathRegex}.`);
    }

    const resourceArn = `arn:aws:execute-api:${region}:${awsAccountId}:${restApiId}/${stage}/${verb}/${formatResource(resource)}`;

    const method = {
      resourceArn,
      conditions,

      hasConditions: () => conditions && conditions.length !== 0
    };

    if (effect === Effect.ALLOW) {
      allowedMethods.push(method);
    } else if (effect === Effect.DENY) {
      deniedMethods.push(method);
    }
  };

  const createEmptyStatement = effect => {
    return {
      Action: Action.EXECUTE_API,
      Effect: effect,
      Resource: []
    };
  };

  const createConditionalStatement = (effect, method) => {
    return {
      Action: Action.EXECUTE_API,
      Effect: effect,
      Resource: [
        method.resourceArn
      ],
      Condition: method.conditions
    };
  };

  const createStatementsForEffect = (effect, methods) => {
    const statements = [];

    if (methods.length === 0) {
      return statements;
    }

    const statement = createEmptyStatement(effect);

    methods.forEach(method => {
      if (method.hasConditions()) {
        statements.push(createConditionalStatement(effect, method));
      } else {
        statement.Resource.push(method.resourceArn);
      }
    });

    if (statement.Resource.length !== 0) {
      statements.push(statement);
    }

    return statements;
  };

  return {

    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
     * methods for the policy
     *
     * @method allowMethod
     * @param {string} The HTTP verb for the method, this should ideally come from the
     *                 authPolicy.HttpVerb object to avoid spelling mistakes
     * @param {string} The resource path. For example "/pets"
     */
    allowMethod: function(verb, resource) {
      addMethod(Effect.ALLOW, verb, resource, null);
      return this;
    },

    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of allowed
     * methods and includes a condition for the policy statement. More on AWS policy
     * conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition
     *
     * @method allowMethodWithConditions
     * @param {string} The HTTP verb for the method, this should ideally come from the
     *                 authPolicy.HttpVerb object to avoid spelling mistakes
     * @param {string} The resource path. For example "/pets"
     * @param {Object} The conditions object in the format specified by the AWS docs
     */
    allowMethodWithConditions: function(verb, resource, conditions) {
      addMethod(Effect.ALLOW, verb, resource, conditions);
      return this;
    },

    /**
     * Adds an allow "*" statement to the policy.
     *
     * @method allowAllMethods
     */
    allowAllMethods: function() {
      addMethod(Effect.ALLOW, HttpVerb.ALL, ALL_RESOURCES, null);
      return this;
    },

    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of denied
     * methods for the policy
     *
     * @method denyMethod
     * @param {string} The HTTP verb for the method, this should ideally come from the
     *                 authPolicy.HttpVerb object to avoid spelling mistakes
     * @param {string} The resource path. For example "/pets"
     */
    denyMethod: function(verb, resource) {
      addMethod(Effect.DENY, verb, resource, null);
      return this;
    },

    /**
     * Adds an API Gateway method (Http verb + Resource path) to the list of denied
     * methods and includes a condition for the policy statement. More on AWS policy
     * conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition
     *
     * @method denyMethodWithConditions
     * @param {string} The HTTP verb for the method, this should ideally come from the
     *                 authPolicy.HttpVerb object to avoid spelling mistakes
     * @param {string} The resource path. For example "/pets"
     * @param {Object} The conditions object in the format specified by the AWS docs
     */
    denyMethodWithConditions: function(verb, resource, conditions) {
      addMethod(Effect.DENY, verb, resource, conditions);
      return this;
    },

    /**
     * Adds a deny "*" statement to the policy.
     *
     * @method denyAllMethods
     */
    denyAllMethods: function() {
      addMethod(Effect.DENY, HttpVerb.ALL, ALL_RESOURCES, null);
      return this;
    },

    /**
     * Adds a custom statement directly in the policy
     *
     * @method addStatement
     * @param {Object} The statement object
     */
    addStatement: function(statement) {
      customStatements.push(statement);
      return this;
    },

    /**
     * Adds a policy context that can be used by the API Gateway with $context.authorizer.<key>
     *
     * @method withContext
     * @param {Object} The context object in key/value format
     */
    withContext: function(ctx) {
      context = ctx;
      return this;
    },

    /**
     * Generates the policy document based on the internal lists of allowed and denied
     * conditions. This will generate a policy with two main statements for the effect:
     * one statement for Allow and one statement for Deny.
     * Methods that includes conditions will have their own statement in the policy.
     *
     * @method build
     * @return {Object} The policy object that can be serialized to JSON
     */
    build: function() {
      if (allowedMethods.length === 0 && deniedMethods.length === 0 && customStatements.length === 0) {
        throw new Error('No statement defined for the policy');
      }

      return {
        principalId: principalId,
        context: context,
        policyDocument: {
          Version: policyVersion,
          Statement: [
            ...createStatementsForEffect(Effect.ALLOW, allowedMethods),
            ...createStatementsForEffect(Effect.DENY, deniedMethods),
            ...customStatements
          ]
        }
      };
    }
  };
}
