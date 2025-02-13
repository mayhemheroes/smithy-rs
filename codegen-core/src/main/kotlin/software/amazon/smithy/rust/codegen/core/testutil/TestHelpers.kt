/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package software.amazon.smithy.rust.codegen.core.testutil

import software.amazon.smithy.codegen.core.Symbol
import software.amazon.smithy.model.Model
import software.amazon.smithy.model.knowledge.NullableIndex
import software.amazon.smithy.model.shapes.OperationShape
import software.amazon.smithy.model.shapes.ServiceShape
import software.amazon.smithy.model.shapes.Shape
import software.amazon.smithy.model.shapes.ShapeId
import software.amazon.smithy.model.shapes.StructureShape
import software.amazon.smithy.model.shapes.UnionShape
import software.amazon.smithy.model.traits.ErrorTrait
import software.amazon.smithy.rust.codegen.core.rustlang.Attribute
import software.amazon.smithy.rust.codegen.core.rustlang.RustModule
import software.amazon.smithy.rust.codegen.core.rustlang.RustReservedWordConfig
import software.amazon.smithy.rust.codegen.core.rustlang.RustReservedWordSymbolProvider
import software.amazon.smithy.rust.codegen.core.rustlang.RustReservedWords
import software.amazon.smithy.rust.codegen.core.rustlang.Visibility
import software.amazon.smithy.rust.codegen.core.rustlang.implBlock
import software.amazon.smithy.rust.codegen.core.smithy.BaseSymbolMetadataProvider
import software.amazon.smithy.rust.codegen.core.smithy.CodegenContext
import software.amazon.smithy.rust.codegen.core.smithy.CodegenTarget
import software.amazon.smithy.rust.codegen.core.smithy.CoreCodegenConfig
import software.amazon.smithy.rust.codegen.core.smithy.CoreRustSettings
import software.amazon.smithy.rust.codegen.core.smithy.ModuleProvider
import software.amazon.smithy.rust.codegen.core.smithy.ModuleProviderContext
import software.amazon.smithy.rust.codegen.core.smithy.RuntimeConfig
import software.amazon.smithy.rust.codegen.core.smithy.RuntimeCrateLocation
import software.amazon.smithy.rust.codegen.core.smithy.RustCrate
import software.amazon.smithy.rust.codegen.core.smithy.RustSymbolProvider
import software.amazon.smithy.rust.codegen.core.smithy.RustSymbolProviderConfig
import software.amazon.smithy.rust.codegen.core.smithy.SymbolVisitor
import software.amazon.smithy.rust.codegen.core.smithy.generators.BuilderGenerator
import software.amazon.smithy.rust.codegen.core.smithy.generators.StructureGenerator
import software.amazon.smithy.rust.codegen.core.smithy.module
import software.amazon.smithy.rust.codegen.core.smithy.traits.SyntheticInputTrait
import software.amazon.smithy.rust.codegen.core.smithy.traits.SyntheticOutputTrait
import software.amazon.smithy.rust.codegen.core.util.dq
import software.amazon.smithy.rust.codegen.core.util.hasTrait
import software.amazon.smithy.rust.codegen.core.util.letIf
import software.amazon.smithy.rust.codegen.core.util.toSnakeCase
import java.io.File

val TestRuntimeConfig =
    RuntimeConfig(runtimeCrateLocation = RuntimeCrateLocation.Path(File("../rust-runtime/").absolutePath))

/**
 * IMPORTANT: You shouldn't need to refer to these directly in code or tests. They are private for a reason.
 *
 * In general, the RustSymbolProvider's `config()` has a `moduleFor` function that should be used
 * to find the destination module for a given shape.
 */
private object CodegenCoreTestModules {
    // Use module paths that don't align with either server or client to make sure
    // the codegen is resilient to differences in module path.
    val ModelsTestModule = RustModule.public("test_model")
    val ErrorsTestModule = RustModule.public("test_error")
    val InputsTestModule = RustModule.public("test_input")
    val OutputsTestModule = RustModule.public("test_output")
    val OperationsTestModule = RustModule.public("test_operation")

    object TestModuleProvider : ModuleProvider {
        override fun moduleForShape(context: ModuleProviderContext, shape: Shape): RustModule.LeafModule =
            when (shape) {
                is OperationShape -> OperationsTestModule
                is StructureShape -> when {
                    shape.hasTrait<ErrorTrait>() -> ErrorsTestModule
                    shape.hasTrait<SyntheticInputTrait>() -> InputsTestModule
                    shape.hasTrait<SyntheticOutputTrait>() -> OutputsTestModule
                    else -> ModelsTestModule
                }

                else -> ModelsTestModule
            }

        override fun moduleForOperationError(
            context: ModuleProviderContext,
            operation: OperationShape,
        ): RustModule.LeafModule = ErrorsTestModule

        override fun moduleForEventStreamError(
            context: ModuleProviderContext,
            eventStream: UnionShape,
        ): RustModule.LeafModule = ErrorsTestModule

        override fun moduleForBuilder(context: ModuleProviderContext, shape: Shape, symbol: Symbol): RustModule.LeafModule {
            val builderNamespace = RustReservedWords.escapeIfNeeded("test_" + symbol.name.toSnakeCase())
            return RustModule.new(
                builderNamespace,
                visibility = Visibility.PUBLIC,
                parent = symbol.module(),
                inline = true,
            )
        }
    }
}

val TestRustSymbolProviderConfig = RustSymbolProviderConfig(
    runtimeConfig = TestRuntimeConfig,
    renameExceptions = true,
    nullabilityCheckMode = NullableIndex.CheckMode.CLIENT_ZERO_VALUE_V1,
    moduleProvider = CodegenCoreTestModules.TestModuleProvider,
)

fun testRustSettings(
    service: ShapeId = ShapeId.from("notrelevant#notrelevant"),
    moduleName: String = "test-module",
    moduleVersion: String = "0.0.1",
    moduleAuthors: List<String> = listOf("notrelevant"),
    moduleDescription: String = "not relevant",
    moduleRepository: String? = null,
    runtimeConfig: RuntimeConfig = TestRuntimeConfig,
    codegenConfig: CoreCodegenConfig = CoreCodegenConfig(),
    license: String? = null,
    examplesUri: String? = null,
) = CoreRustSettings(
    service,
    moduleName,
    moduleVersion,
    moduleAuthors,
    moduleDescription,
    moduleRepository,
    runtimeConfig,
    codegenConfig,
    license,
    examplesUri,
)

private const val SmithyVersion = "1.0"
fun String.asSmithyModel(sourceLocation: String? = null, smithyVersion: String = SmithyVersion): Model {
    val processed = letIf(!this.trimStart().startsWith("\$version")) { "\$version: ${smithyVersion.dq()}\n$it" }
    return Model.assembler().discoverModels().addUnparsedModel(sourceLocation ?: "test.smithy", processed).assemble()
        .unwrap()
}

// Intentionally only visible to codegen-core since the other modules have their own symbol providers
internal fun testSymbolProvider(
    model: Model,
    rustReservedWordConfig: RustReservedWordConfig? = null,
): RustSymbolProvider = SymbolVisitor(
    testRustSettings(),
    model,
    ServiceShape.builder().version("test").id("test#Service").build(),
    TestRustSymbolProviderConfig,
).let { BaseSymbolMetadataProvider(it, additionalAttributes = listOf(Attribute.NonExhaustive)) }
    .let {
        RustReservedWordSymbolProvider(
            it,
            rustReservedWordConfig ?: RustReservedWordConfig(emptyMap(), emptyMap(), emptyMap()),
        )
    }

// Intentionally only visible to codegen-core since the other modules have their own contexts
internal fun testCodegenContext(
    model: Model,
    serviceShape: ServiceShape? = null,
    settings: CoreRustSettings = testRustSettings(),
    codegenTarget: CodegenTarget = CodegenTarget.CLIENT,
): CodegenContext = CodegenContext(
    model,
    testSymbolProvider(model),
    TestModuleDocProvider,
    serviceShape
        ?: model.serviceShapes.firstOrNull()
        ?: ServiceShape.builder().version("test").id("test#Service").build(),
    ShapeId.from("test#Protocol"),
    settings,
    codegenTarget,
)

/**
 * In tests, we frequently need to generate a struct, a builder, and an impl block to access said builder.
 */
fun StructureShape.renderWithModelBuilder(
    model: Model,
    symbolProvider: RustSymbolProvider,
    rustCrate: RustCrate,
) {
    val struct = this
    rustCrate.withModule(symbolProvider.moduleForShape(struct)) {
        StructureGenerator(model, symbolProvider, this, struct, emptyList()).render()
        implBlock(symbolProvider.toSymbol(struct)) {
            BuilderGenerator.renderConvenienceMethod(this, symbolProvider, struct)
        }
    }
    rustCrate.withModule(symbolProvider.moduleForBuilder(struct)) {
        BuilderGenerator(model, symbolProvider, struct, emptyList()).render(this)
    }
}
