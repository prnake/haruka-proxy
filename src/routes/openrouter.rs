use axum::{
    extract::DefaultBodyLimit,
    routing::post,
    Router,
};
use tower_http::limit::RequestBodyLimitLayer;

use crate::handlers::openrouter;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(openrouter::handle_post))
        .route(
            "/msgs_forward/{domain}/v1/chat/completions",
            post(openrouter::handle_msgs_forward),
        )
        .route(
            "/msgs_forward/{domain}/v1/messages",
            post(openrouter::handle_msgs_forward),
        )
        .route(
            "/chat_forward/{domain_type}/v1/chat/completions",
            post(openrouter::handle_chat_completions_forward),
        )
        .route(
            "/gemini_forward/{domain}/v1/chat/completions",
            post(openrouter::handle_gemini_forward),
        )
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024))
        .with_state(state)
}

