/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use aws_http::user_agent::AwsUserAgent;
use aws_runtime::invocation_id::InvocationId;
use aws_smithy_runtime_api::client::interceptors::context::phase::BeforeTransmit;
use aws_smithy_runtime_api::client::interceptors::{
    Interceptor, InterceptorContext, InterceptorRegistrar,
};
use aws_smithy_runtime_api::client::orchestrator::{ConfigBagAccessors, RequestTime};
use aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugin;
use aws_smithy_runtime_api::config_bag::ConfigBag;
use http::header::USER_AGENT;
use http::{HeaderName, HeaderValue};
use std::time::SystemTime;

pub const X_AMZ_USER_AGENT: HeaderName = HeaderName::from_static("x-amz-user-agent");

#[derive(Debug)]
pub struct FixupPlugin {
    pub timestamp: SystemTime,
}
impl RuntimePlugin for FixupPlugin {
    fn configure(
        &self,
        cfg: &mut ConfigBag,
        _interceptors: &mut InterceptorRegistrar,
    ) -> Result<(), aws_smithy_runtime_api::client::runtime_plugin::BoxError> {
        cfg.set_request_time(RequestTime::new(self.timestamp.clone()));
        cfg.put(InvocationId::for_tests());
        Ok(())
    }
}

#[derive(Debug)]
pub struct TestUserAgentInterceptor;
impl Interceptor for TestUserAgentInterceptor {
    fn modify_before_signing(
        &self,
        context: &mut InterceptorContext<BeforeTransmit>,
        _cfg: &mut ConfigBag,
    ) -> Result<(), aws_smithy_runtime_api::client::interceptors::BoxError> {
        let headers = context.request_mut().headers_mut();
        let user_agent = AwsUserAgent::for_tests();
        // Overwrite user agent header values provided by `UserAgentInterceptor`
        headers.insert(USER_AGENT, HeaderValue::try_from(user_agent.ua_header())?);
        headers.insert(
            X_AMZ_USER_AGENT,
            HeaderValue::try_from(user_agent.aws_ua_header())?,
        );

        Ok(())
    }
}
