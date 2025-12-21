use axum::{extract::DefaultBodyLimit, routing::post, Router};
use tower_http::limit::RequestBodyLimitLayer;

use crate::handlers::bedrock;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/bedrock/v1/messages", post(bedrock::handle_messages_endpoint))
        .route("/bedrock/messages", post(bedrock::handle_messages_endpoint))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024))
        .with_state(state)
}

