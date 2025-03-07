/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.smithy.rustsdk.customize.s3

import software.amazon.smithy.aws.traits.protocols.RestXmlTrait
import software.amazon.smithy.model.Model
import software.amazon.smithy.model.node.Node
import software.amazon.smithy.model.shapes.OperationShape
import software.amazon.smithy.model.shapes.ServiceShape
import software.amazon.smithy.model.shapes.Shape
import software.amazon.smithy.model.shapes.ShapeId
import software.amazon.smithy.model.shapes.StructureShape
import software.amazon.smithy.model.transform.ModelTransformer
import software.amazon.smithy.rulesengine.traits.EndpointTestCase
import software.amazon.smithy.rulesengine.traits.EndpointTestOperationInput
import software.amazon.smithy.rulesengine.traits.EndpointTestsTrait
import software.amazon.smithy.rust.codegen.client.smithy.ClientCodegenContext
import software.amazon.smithy.rust.codegen.client.smithy.customize.ClientCodegenDecorator
import software.amazon.smithy.rust.codegen.client.smithy.endpoint.EndpointCustomization
import software.amazon.smithy.rust.codegen.client.smithy.endpoint.rustName
import software.amazon.smithy.rust.codegen.client.smithy.generators.protocol.ClientProtocolGenerator
import software.amazon.smithy.rust.codegen.client.smithy.protocols.ClientRestXmlFactory
import software.amazon.smithy.rust.codegen.core.rustlang.Writable
import software.amazon.smithy.rust.codegen.core.rustlang.rustBlockTemplate
import software.amazon.smithy.rust.codegen.core.rustlang.rustTemplate
import software.amazon.smithy.rust.codegen.core.rustlang.writable
import software.amazon.smithy.rust.codegen.core.smithy.CodegenContext
import software.amazon.smithy.rust.codegen.core.smithy.RuntimeType
import software.amazon.smithy.rust.codegen.core.smithy.protocols.ProtocolFunctions
import software.amazon.smithy.rust.codegen.core.smithy.protocols.ProtocolMap
import software.amazon.smithy.rust.codegen.core.smithy.protocols.RestXml
import software.amazon.smithy.rust.codegen.core.smithy.traits.AllowInvalidXmlRoot
import software.amazon.smithy.rust.codegen.core.util.letIf
import software.amazon.smithy.rustsdk.getBuiltIn
import software.amazon.smithy.rustsdk.toWritable
import java.util.logging.Logger

/**
 * Top level decorator for S3
 */
class S3Decorator : ClientCodegenDecorator {
    override val name: String = "S3"
    override val order: Byte = 0
    private val logger: Logger = Logger.getLogger(javaClass.name)
    private val invalidXmlRootAllowList = setOf(
        // API returns GetObjectAttributes_Response_ instead of Output
        ShapeId.from("com.amazonaws.s3#GetObjectAttributesOutput"),
    )

    override fun protocols(
        serviceId: ShapeId,
        currentProtocols: ProtocolMap<ClientProtocolGenerator, ClientCodegenContext>,
    ): ProtocolMap<ClientProtocolGenerator, ClientCodegenContext> = currentProtocols + mapOf(
        RestXmlTrait.ID to ClientRestXmlFactory { protocolConfig ->
            S3ProtocolOverride(protocolConfig)
        },
    )

    override fun transformModel(service: ServiceShape, model: Model): Model =
        ModelTransformer.create().mapShapes(model) { shape ->
            shape.letIf(isInInvalidXmlRootAllowList(shape)) {
                logger.info("Adding AllowInvalidXmlRoot trait to $it")
                (it as StructureShape).toBuilder().addTrait(AllowInvalidXmlRoot()).build()
            }
        }
            // the model has the bucket in the path
            .let(StripBucketFromHttpPath()::transform)
            // the tests in EP2 are incorrect and are missing request route
            .let(
                FilterEndpointTests(
                    operationInputFilter = { input ->
                        when (input.operationName) {
                            // it's impossible to express HostPrefix behavior in the current EP2 rules schema :-/
                            // A handwritten test was written to cover this behavior
                            "WriteGetObjectResponse" -> null
                            else -> input
                        }
                    },
                )::transform,
            )

    override fun endpointCustomizations(codegenContext: ClientCodegenContext): List<EndpointCustomization> {
        return listOf(
            object : EndpointCustomization {
                override fun setBuiltInOnServiceConfig(name: String, value: Node, configBuilderRef: String): Writable? {
                    if (!name.startsWith("AWS::S3")) {
                        return null
                    }
                    val builtIn = codegenContext.getBuiltIn(name) ?: return null
                    return writable {
                        rustTemplate(
                            "let $configBuilderRef = $configBuilderRef.${builtIn.name.rustName()}(#{value});",
                            "value" to value.toWritable(),
                        )
                    }
                }
            },
        )
    }

    private fun isInInvalidXmlRootAllowList(shape: Shape): Boolean {
        return shape.isStructureShape && invalidXmlRootAllowList.contains(shape.id)
    }
}

class FilterEndpointTests(
    private val testFilter: (EndpointTestCase) -> EndpointTestCase? = { a -> a },
    private val operationInputFilter: (EndpointTestOperationInput) -> EndpointTestOperationInput? = { a -> a },
) {
    fun updateEndpointTests(endpointTests: List<EndpointTestCase>): List<EndpointTestCase> {
        val filteredTests = endpointTests.mapNotNull { test -> testFilter(test) }
        return filteredTests.map { test ->
            val operationInputs = test.operationInputs
            test.toBuilder().operationInputs(operationInputs.mapNotNull { operationInputFilter(it) }).build()
        }
    }

    fun transform(model: Model) = ModelTransformer.create().mapTraits(model) { _, trait ->
        when (trait) {
            is EndpointTestsTrait -> EndpointTestsTrait.builder().testCases(updateEndpointTests(trait.testCases))
                .version(trait.version).build()

            else -> trait
        }
    }
}

class S3ProtocolOverride(codegenContext: CodegenContext) : RestXml(codegenContext) {
    private val runtimeConfig = codegenContext.runtimeConfig
    private val errorScope = arrayOf(
        *RuntimeType.preludeScope,
        "Bytes" to RuntimeType.Bytes,
        "ErrorMetadata" to RuntimeType.errorMetadata(runtimeConfig),
        "ErrorBuilder" to RuntimeType.errorMetadataBuilder(runtimeConfig),
        "HeaderMap" to RuntimeType.HttpHeaderMap,
        "Response" to RuntimeType.HttpResponse,
        "XmlDecodeError" to RuntimeType.smithyXml(runtimeConfig).resolve("decode::XmlDecodeError"),
        "base_errors" to restXmlErrors,
    )

    override fun parseHttpErrorMetadata(operationShape: OperationShape): RuntimeType {
        return ProtocolFunctions.crossOperationFn("parse_http_error_metadata") { fnName ->
            rustBlockTemplate(
                "pub fn $fnName(response_status: u16, _response_headers: &#{HeaderMap}, response_body: &[u8]) -> #{Result}<#{ErrorBuilder}, #{XmlDecodeError}>",
                *errorScope,
            ) {
                rustTemplate(
                    """
                    // S3 HEAD responses have no response body to for an error code. Therefore,
                    // check the HTTP response status and populate an error code for 404s.
                    if response_body.is_empty() {
                        let mut builder = #{ErrorMetadata}::builder();
                        if response_status == 404 {
                            builder = builder.code("NotFound");
                        }
                        Ok(builder)
                    } else {
                        #{base_errors}::parse_error_metadata(response_body)
                    }
                    """,
                    *errorScope,
                )
            }
        }
    }
}
