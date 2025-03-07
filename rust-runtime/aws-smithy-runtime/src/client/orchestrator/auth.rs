/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::{bail, handle_err};
use aws_smithy_http::result::SdkError;
use aws_smithy_runtime_api::client::interceptors::context::{AttemptCheckpoint, Error};
use aws_smithy_runtime_api::client::orchestrator::{BoxError, ConfigBagAccessors, HttpResponse};
use aws_smithy_runtime_api::config_bag::ConfigBag;

pub(super) async fn orchestrate_auth(
    mut checkpoint: AttemptCheckpoint,
    cfg: &ConfigBag,
) -> Result<AttemptCheckpoint, SdkError<Error, HttpResponse>> {
    fn construction_failure(err: impl Into<BoxError>) -> SdkError<Error, HttpResponse> {
        SdkError::construction_failure(err)
    }

    let params = cfg.auth_option_resolver_params();
    let auth_options = cfg
        .auth_option_resolver()
        .resolve_auth_options(params)
        .map_err(construction_failure)?;
    let identity_resolvers = cfg.identity_resolvers();

    tracing::trace!(
        auth_option_resolver_params = ?params,
        auth_options = ?auth_options,
        identity_resolvers = ?identity_resolvers,
        "orchestrating auth",
    );
    for &scheme_id in auth_options.as_ref() {
        if let Some(auth_scheme) = cfg.http_auth_schemes().scheme(scheme_id) {
            if let Some(identity_resolver) = auth_scheme.identity_resolver(identity_resolvers) {
                let request_signer = auth_scheme.request_signer();

                let identity = identity_resolver
                    .resolve_identity(cfg)
                    .await
                    .map_err(construction_failure)?;
                let request = checkpoint.before_transmit().request_mut();
                handle_err!([checkpoint] => request_signer.sign_request(request, &identity, cfg));
                return Ok(checkpoint);
            }
        }
    }

    bail!(
        [checkpoint],
        "no auth scheme matched auth options. This is a bug. Please file an issue."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_http::body::SdkBody;
    use aws_smithy_runtime_api::client::auth::option_resolver::StaticAuthOptionResolver;
    use aws_smithy_runtime_api::client::auth::{
        AuthOptionResolverParams, AuthSchemeId, HttpAuthScheme, HttpAuthSchemes, HttpRequestSigner,
    };
    use aws_smithy_runtime_api::client::identity::{Identity, IdentityResolver, IdentityResolvers};
    use aws_smithy_runtime_api::client::interceptors::InterceptorContext;
    use aws_smithy_runtime_api::client::orchestrator::{Future, HttpRequest};
    use aws_smithy_runtime_api::type_erasure::TypedBox;

    #[tokio::test]
    async fn basic_case() {
        #[derive(Debug)]
        struct TestIdentityResolver;
        impl IdentityResolver for TestIdentityResolver {
            fn resolve_identity(&self, _config_bag: &ConfigBag) -> Future<Identity> {
                Future::ready(Ok(Identity::new("doesntmatter", None)))
            }
        }

        #[derive(Debug)]
        struct TestSigner;

        impl HttpRequestSigner for TestSigner {
            fn sign_request(
                &self,
                request: &mut HttpRequest,
                _identity: &Identity,
                _config_bag: &ConfigBag,
            ) -> Result<(), BoxError> {
                request
                    .headers_mut()
                    .insert(http::header::AUTHORIZATION, "success!".parse().unwrap());
                Ok(())
            }
        }

        const TEST_SCHEME_ID: AuthSchemeId = AuthSchemeId::new("test-scheme");

        #[derive(Debug)]
        struct TestAuthScheme {
            signer: TestSigner,
        }
        impl HttpAuthScheme for TestAuthScheme {
            fn scheme_id(&self) -> AuthSchemeId {
                TEST_SCHEME_ID
            }

            fn identity_resolver<'a>(
                &self,
                identity_resolvers: &'a IdentityResolvers,
            ) -> Option<&'a dyn IdentityResolver> {
                identity_resolvers.identity_resolver(self.scheme_id())
            }

            fn request_signer(&self) -> &dyn HttpRequestSigner {
                &self.signer
            }
        }

        let input = TypedBox::new("doesnt-matter").erase();
        let mut context = InterceptorContext::<()>::new(input).into_serialization_phase();
        context.set_request(http::Request::builder().body(SdkBody::empty()).unwrap());
        let _ = context.take_input();
        let checkpoint = AttemptCheckpoint::new(context.into_before_transmit_phase());

        let mut cfg = ConfigBag::base();
        cfg.set_auth_option_resolver_params(AuthOptionResolverParams::new("doesntmatter"));
        cfg.set_auth_option_resolver(StaticAuthOptionResolver::new(vec![TEST_SCHEME_ID]));
        cfg.set_identity_resolvers(
            IdentityResolvers::builder()
                .identity_resolver(TEST_SCHEME_ID, TestIdentityResolver)
                .build(),
        );
        cfg.set_http_auth_schemes(
            HttpAuthSchemes::builder()
                .auth_scheme(TEST_SCHEME_ID, TestAuthScheme { signer: TestSigner })
                .build(),
        );

        let mut checkpoint = orchestrate_auth(checkpoint, &cfg).await.expect("success");

        assert_eq!(
            "success!",
            checkpoint
                .before_transmit()
                .request()
                .headers()
                .get("Authorization")
                .unwrap()
        );
    }

    #[cfg(feature = "http-auth")]
    #[tokio::test]
    async fn select_best_scheme_for_available_identity_resolvers() {
        use crate::client::auth::http::{BasicAuthScheme, BearerAuthScheme};
        use aws_smithy_runtime_api::client::auth::http::{
            HTTP_BASIC_AUTH_SCHEME_ID, HTTP_BEARER_AUTH_SCHEME_ID,
        };
        use aws_smithy_runtime_api::client::identity::http::{Login, Token};

        let mut context = InterceptorContext::<()>::new(TypedBox::new("doesnt-matter").erase())
            .into_serialization_phase();
        context.set_request(http::Request::builder().body(SdkBody::empty()).unwrap());
        let _ = context.take_input();
        let checkpoint = AttemptCheckpoint::new(context.into_before_transmit_phase());

        let mut cfg = ConfigBag::base();
        cfg.set_auth_option_resolver_params(AuthOptionResolverParams::new("doesntmatter"));
        cfg.set_auth_option_resolver(StaticAuthOptionResolver::new(vec![
            HTTP_BASIC_AUTH_SCHEME_ID,
            HTTP_BEARER_AUTH_SCHEME_ID,
        ]));
        cfg.set_http_auth_schemes(
            HttpAuthSchemes::builder()
                .auth_scheme(HTTP_BASIC_AUTH_SCHEME_ID, BasicAuthScheme::new())
                .auth_scheme(HTTP_BEARER_AUTH_SCHEME_ID, BearerAuthScheme::new())
                .build(),
        );

        // First, test the presence of a basic auth login and absence of a bearer token
        cfg.set_identity_resolvers(
            IdentityResolvers::builder()
                .identity_resolver(HTTP_BASIC_AUTH_SCHEME_ID, Login::new("a", "b", None))
                .build(),
        );

        let mut checkpoint = orchestrate_auth(checkpoint, &cfg).await.expect("success");

        assert_eq!(
            // "YTpi" == "a:b" in base64
            "Basic YTpi",
            checkpoint
                .before_transmit()
                .request()
                .headers()
                .get("Authorization")
                .unwrap()
        );

        // Next, test the presence of a bearer token and absence of basic auth
        cfg.set_identity_resolvers(
            IdentityResolvers::builder()
                .identity_resolver(HTTP_BEARER_AUTH_SCHEME_ID, Token::new("t", None))
                .build(),
        );

        let mut context = InterceptorContext::<()>::new(TypedBox::new("doesnt-matter").erase())
            .into_serialization_phase();
        context.set_request(http::Request::builder().body(SdkBody::empty()).unwrap());
        let _ = context.take_input();
        let checkpoint = AttemptCheckpoint::new(context.into_before_transmit_phase());

        let mut checkpoint = orchestrate_auth(checkpoint, &cfg).await.expect("success");
        assert_eq!(
            "Bearer t",
            checkpoint
                .before_transmit()
                .request()
                .headers()
                .get("Authorization")
                .unwrap()
        );
    }
}
