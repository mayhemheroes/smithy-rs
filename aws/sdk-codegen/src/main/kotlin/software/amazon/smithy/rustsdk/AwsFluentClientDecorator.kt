/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.smithy.rustsdk

import software.amazon.smithy.rust.codegen.client.smithy.ClientCodegenContext
import software.amazon.smithy.rust.codegen.client.smithy.ClientRustModule
import software.amazon.smithy.rust.codegen.client.smithy.customize.ClientCodegenDecorator
import software.amazon.smithy.rust.codegen.client.smithy.generators.client.FluentClientCustomization
import software.amazon.smithy.rust.codegen.client.smithy.generators.client.FluentClientDocs
import software.amazon.smithy.rust.codegen.client.smithy.generators.client.FluentClientGenerator
import software.amazon.smithy.rust.codegen.client.smithy.generators.client.FluentClientGenerics
import software.amazon.smithy.rust.codegen.client.smithy.generators.client.FluentClientSection
import software.amazon.smithy.rust.codegen.client.smithy.generators.client.NoClientGenerics
import software.amazon.smithy.rust.codegen.core.rustlang.Attribute
import software.amazon.smithy.rust.codegen.core.rustlang.Feature
import software.amazon.smithy.rust.codegen.core.rustlang.GenericTypeArg
import software.amazon.smithy.rust.codegen.core.rustlang.RustGenerics
import software.amazon.smithy.rust.codegen.core.rustlang.RustWriter
import software.amazon.smithy.rust.codegen.core.rustlang.Writable
import software.amazon.smithy.rust.codegen.core.rustlang.rust
import software.amazon.smithy.rust.codegen.core.rustlang.rustBlockTemplate
import software.amazon.smithy.rust.codegen.core.rustlang.rustTemplate
import software.amazon.smithy.rust.codegen.core.rustlang.writable
import software.amazon.smithy.rust.codegen.core.smithy.RuntimeConfig
import software.amazon.smithy.rust.codegen.core.smithy.RuntimeType
import software.amazon.smithy.rust.codegen.core.smithy.RustCrate
import software.amazon.smithy.rust.codegen.core.smithy.generators.LibRsCustomization
import software.amazon.smithy.rust.codegen.core.smithy.generators.LibRsSection
import software.amazon.smithy.rust.codegen.core.util.serviceNameOrDefault
import software.amazon.smithy.rustsdk.AwsRuntimeType.defaultMiddleware

private class Types(runtimeConfig: RuntimeConfig) {
    private val smithyClient = RuntimeType.smithyClient(runtimeConfig)
    private val smithyHttp = RuntimeType.smithyHttp(runtimeConfig)
    private val smithyTypes = RuntimeType.smithyTypes(runtimeConfig)

    val awsTypes = AwsRuntimeType.awsTypes(runtimeConfig)
    val connectorError = smithyHttp.resolve("result::ConnectorError")
    val connectorSettings = smithyClient.resolve("http_connector::ConnectorSettings")
    val defaultMiddleware = runtimeConfig.defaultMiddleware()
    val dynConnector = smithyClient.resolve("erase::DynConnector")
    val dynMiddleware = smithyClient.resolve("erase::DynMiddleware")
    val retryConfig = smithyTypes.resolve("retry::RetryConfig")
    val smithyClientBuilder = smithyClient.resolve("Builder")
    val smithyClientRetry = smithyClient.resolve("retry")
    val smithyConnector = smithyClient.resolve("bounds::SmithyConnector")
    val timeoutConfig = smithyTypes.resolve("timeout::TimeoutConfig")
}

class AwsFluentClientDecorator : ClientCodegenDecorator {
    override val name: String = "FluentClient"

    // Must run after the AwsPresigningDecorator so that the presignable trait is correctly added to operations
    override val order: Byte = (AwsPresigningDecorator.ORDER + 1).toByte()

    override fun extras(codegenContext: ClientCodegenContext, rustCrate: RustCrate) {
        val runtimeConfig = codegenContext.runtimeConfig
        val types = Types(runtimeConfig)
        val generics = NoClientGenerics(runtimeConfig)
        FluentClientGenerator(
            codegenContext,
            reexportSmithyClientBuilder = false,
            generics = generics,
            customizations = listOf(
                AwsPresignedFluentBuilderMethod(runtimeConfig),
                AwsFluentClientDocs(codegenContext),
            ),
            retryClassifier = AwsRuntimeType.awsHttp(runtimeConfig).resolve("retry::AwsResponseRetryClassifier"),
        ).render(rustCrate)
        rustCrate.withModule(ClientRustModule.Client.customize) {
            renderCustomizableOperationSendMethod(runtimeConfig, generics, this)
        }
        rustCrate.withModule(ClientRustModule.client) {
            AwsFluentClientExtensions(types).render(this)
        }
        val awsSmithyClient = "aws-smithy-client"
        rustCrate.mergeFeature(Feature("rustls", default = true, listOf("$awsSmithyClient/rustls")))
        rustCrate.mergeFeature(Feature("native-tls", default = false, listOf("$awsSmithyClient/native-tls")))
    }

    override fun libRsCustomizations(
        codegenContext: ClientCodegenContext,
        baseCustomizations: List<LibRsCustomization>,
    ): List<LibRsCustomization> {
        return baseCustomizations + object : LibRsCustomization() {
            override fun section(section: LibRsSection) = when (section) {
                is LibRsSection.Body -> writable {
                    Attribute.DocInline.render(this)
                    rust("pub use client::Client;")
                }

                else -> emptySection
            }
        }
    }
}

private class AwsFluentClientExtensions(types: Types) {
    private val codegenScope = arrayOf(
        "ConnectorError" to types.connectorError,
        "DynConnector" to types.dynConnector,
        "DynMiddleware" to types.dynMiddleware,
        "ConnectorSettings" to types.connectorSettings,
        "Middleware" to types.defaultMiddleware,
        "RetryConfig" to types.retryConfig,
        "SmithyConnector" to types.smithyConnector,
        "TimeoutConfig" to types.timeoutConfig,
        "SmithyClientBuilder" to types.smithyClientBuilder,
        "aws_types" to types.awsTypes,
        "retry" to types.smithyClientRetry,
    )

    fun render(writer: RustWriter) {
        writer.rustBlockTemplate("impl Client", *codegenScope) {
            rustTemplate(
                """
                /// Creates a new client from an [SDK Config](#{aws_types}::sdk_config::SdkConfig).
                ///
                /// ## Panics
                ///
                /// - This method will panic if the `sdk_config` is missing an async sleep implementation. If you experience this panic, set
                ///     the `sleep_impl` on the Config passed into this function to fix it.
                /// - This method will panic if the `sdk_config` is missing an HTTP connector. If you experience this panic, set the
                ///     `http_connector` on the Config passed into this function to fix it.
                pub fn new(sdk_config: &#{aws_types}::sdk_config::SdkConfig) -> Self {
                    Self::from_conf(sdk_config.into())
                }

                /// Creates a new client from the service [`Config`](crate::Config).
                ///
                /// ## Panics
                ///
                /// - This method will panic if the `conf` is missing an async sleep implementation. If you experience this panic, set
                ///     the `sleep_impl` on the Config passed into this function to fix it.
                /// - This method will panic if the `conf` is missing an HTTP connector. If you experience this panic, set the
                ///     `http_connector` on the Config passed into this function to fix it.
                pub fn from_conf(conf: crate::Config) -> Self {
                    let retry_config = conf.retry_config().cloned().unwrap_or_else(#{RetryConfig}::disabled);
                    let timeout_config = conf.timeout_config().cloned().unwrap_or_else(#{TimeoutConfig}::disabled);
                    let sleep_impl = conf.sleep_impl();
                    if (retry_config.has_retry() || timeout_config.has_timeouts()) && sleep_impl.is_none() {
                        panic!("An async sleep implementation is required for retries or timeouts to work. \
                                Set the `sleep_impl` on the Config passed into this function to fix this panic.");
                    }

                    let connector = conf.http_connector().and_then(|c| {
                        let timeout_config = conf
                            .timeout_config()
                            .cloned()
                            .unwrap_or_else(#{TimeoutConfig}::disabled);
                        let connector_settings = #{ConnectorSettings}::from_timeout_config(
                            &timeout_config,
                        );
                        c.connector(&connector_settings, conf.sleep_impl())
                    });

                    let builder = #{SmithyClientBuilder}::new();

                    let builder = match connector {
                        // Use provided connector
                        Some(c) => builder.connector(c),
                        None =>{
                            ##[cfg(any(feature = "rustls", feature = "native-tls"))]
                            {
                                // Use default connector based on enabled features
                                builder.dyn_https_connector(#{ConnectorSettings}::from_timeout_config(&timeout_config))
                            }
                            ##[cfg(not(any(feature = "rustls", feature = "native-tls")))]
                            {
                                panic!("No HTTP connector was available. Enable the `rustls` or `native-tls` crate feature or set a connector to fix this.");
                            }
                        }
                    };
                    let mut builder = builder
                        .middleware(#{DynMiddleware}::new(#{Middleware}::new()))
                        .reconnect_mode(retry_config.reconnect_mode())
                        .retry_config(retry_config.into())
                        .operation_timeout_config(timeout_config.into());
                    builder.set_sleep_impl(sleep_impl);
                    let client = builder.build();

                    Self { handle: std::sync::Arc::new(Handle { client, conf }) }
                }
                """,
                *codegenScope,
            )
        }
    }
}

private class AwsFluentClientDocs(private val codegenContext: ClientCodegenContext) : FluentClientCustomization() {
    private val serviceName = codegenContext.serviceShape.serviceNameOrDefault("the service")

    override fun section(section: FluentClientSection): Writable {
        return when (section) {
            is FluentClientSection.FluentClientDocs -> writable {
                rustTemplate(
                    """
                    /// Client for $serviceName
                    ///
                    /// Client for invoking operations on $serviceName. Each operation on $serviceName is a method on this
                    /// this struct. `.send()` MUST be invoked on the generated operations to dispatch the request to the service.""",
                )
                AwsDocs.clientConstructionDocs(codegenContext)(this)
                FluentClientDocs.clientUsageDocs(codegenContext)(this)
            }

            else -> emptySection
        }
    }
}

private fun renderCustomizableOperationSendMethod(
    runtimeConfig: RuntimeConfig,
    generics: FluentClientGenerics,
    writer: RustWriter,
) {
    val operationGenerics = RustGenerics(GenericTypeArg("O"), GenericTypeArg("Retry"))
    val handleGenerics = generics.toRustGenerics()
    val combinedGenerics = operationGenerics + handleGenerics

    val codegenScope = arrayOf(
        *RuntimeType.preludeScope,
        "combined_generics_decl" to combinedGenerics.declaration(),
        "handle_generics_bounds" to handleGenerics.bounds(),
        "SdkSuccess" to RuntimeType.sdkSuccess(runtimeConfig),
        "SdkError" to RuntimeType.sdkError(runtimeConfig),
        "ClassifyRetry" to RuntimeType.classifyRetry(runtimeConfig),
        "ParseHttpResponse" to RuntimeType.parseHttpResponse(runtimeConfig),
    )

    writer.rustTemplate(
        """
        impl#{combined_generics_decl:W} CustomizableOperation#{combined_generics_decl:W}
        where
            #{handle_generics_bounds:W}
        {
            /// Sends this operation's request
            pub async fn send<T, E>(self) -> #{Result}<T, #{SdkError}<E>>
            where
                E: std::error::Error + #{Send} + #{Sync} + 'static,
                O: #{ParseHttpResponse}<Output = #{Result}<T, E>> + #{Send} + #{Sync} + #{Clone} + 'static,
                Retry: #{ClassifyRetry}<#{SdkSuccess}<T>, #{SdkError}<E>> + #{Send} + #{Sync} + #{Clone},
            {
                self.handle.client.call(self.operation).await
            }
        }
        """,
        *codegenScope,
    )
}
