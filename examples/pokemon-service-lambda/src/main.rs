/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::sync::Arc;

use aws_smithy_http_server::{routing::LambdaHandler, AddExtensionLayer};

use pokemon_service_common::{
    capture_pokemon, check_health, do_nothing, get_pokemon_species, get_server_statistics,
    setup_tracing, State,
};
use pokemon_service_lambda::get_storage_lambda;
use pokemon_service_server_sdk::PokemonService;

#[tokio::main]
pub async fn main() {
    setup_tracing();

    let app = PokemonService::builder_without_plugins()
        // Build a registry containing implementations to all the operations in the service. These
        // are async functions or async closures that take as input the operation's input and
        // return the operation's output.
        .get_pokemon_species(get_pokemon_species)
        .get_storage(get_storage_lambda)
        .get_server_statistics(get_server_statistics)
        .capture_pokemon(capture_pokemon)
        .do_nothing(do_nothing)
        .check_health(check_health)
        .build()
        .expect("failed to build an instance of PokemonService")
        // Set up shared state and middlewares.
        .layer(&AddExtensionLayer::new(Arc::new(State::default())));

    let handler = LambdaHandler::new(app);
    let lambda = lambda_http::run(handler);

    if let Err(err) = lambda.await {
        eprintln!("lambda error: {}", err);
    }
}
