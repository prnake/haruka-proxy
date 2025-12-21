use axum::{
    extract::DefaultBodyLimit,
    routing::post,
    Router,
};
use tower_http::limit::RequestBodyLimitLayer;

use crate::handlers::vertex;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/vertex/v1/messages", post(vertex::handle_messages_endpoint))
        .route("/vertex/messages", post(vertex::handle_messages_endpoint))
        .route("/vertex/v1/count-tokens", post(vertex::handle_count_tokens_endpoint))
        .route("/vertex/count-tokens", post(vertex::handle_count_tokens_endpoint))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024))
        .with_state(state)
}

