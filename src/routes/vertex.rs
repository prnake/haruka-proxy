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
        // Anthropic Claude on Vertex AI
        .route("/vertex/v1/messages", post(vertex::handle_messages_endpoint))
        .route("/vertex/messages", post(vertex::handle_messages_endpoint))
        .route("/vertex/v1/count-tokens", post(vertex::handle_count_tokens_endpoint))
        .route("/vertex/count-tokens", post(vertex::handle_count_tokens_endpoint))
        // Gemini API 格式（透传到 Vertex AI Google 模型）
        // 例如: /v1beta/models/gemini-3-pro-image-preview:streamGenerateContent?key=xxx
        .route("/v1beta/models/{model_action}", post(vertex::handle_gemini_endpoint))
        .route("/v1/models/{model_action}", post(vertex::handle_gemini_endpoint))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024))
        .with_state(state)
}
