use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::{collections::HashMap, fs, net::SocketAddr};
use tokio::net::TcpListener;
use tracing::{error, info};

// 1. AppState 需要实现 Clone
#[derive(Clone)]
struct AppState {
    model_map: &'static HashMap<String, String>,
    client: reqwest::Client,
}

// 读取 models.json 到全局静态变量
static MODEL_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let data = fs::read_to_string("models.json").expect("Failed to read models.json");
    serde_json::from_str(&data).expect("Invalid models.json format")
});

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let state = AppState {
        model_map: &MODEL_MAP,
        client: reqwest::Client::new(),
    };

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_post))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 30033));
    info!("🚀 Server listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}


async fn handle_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> impl IntoResponse {
    if !headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.starts_with("application/json"))
    {
        return (StatusCode::BAD_REQUEST, "Unsupported content type").into_response();
    }

    if let Some(model_val) = body.get("model").and_then(|m| m.as_str()) {
        let mapped_model = handle_model_name(model_val, state.model_map);
        body["model"] = json!(mapped_model);
    } else {
        return (StatusCode::BAD_REQUEST, "Missing model").into_response();
    }


    
    let mut forward_headers = HeaderMap::new();
    forward_headers.insert("content-type", "application/json".parse().unwrap());
    if let Some(auth) = headers.get("authorization") {
        forward_headers.insert("authorization", auth.clone());
    }
    
    let res = state
        .client
        .post("https://openrouter.ai/api/v1/chat/completions")
        .headers(forward_headers)
        .json(&body)
        .send()
        .await;

    match res {
        Ok(resp) => {
            let mut response_builder = Response::builder().status(resp.status());
            if let Some(headers) = response_builder.headers_mut() {
                *headers = resp.headers().clone();
            }
            response_builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap()
        }
        Err(err) => {
            error!("Forward request failed: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error: {}", err),
            )
                .into_response()
        }
    }
}

fn handle_model_name<'a>(model_name: &'a str, model_map: &'a HashMap<String, String>) -> String {
    let mut name = model_name;

    for prefix in ["openrouter:", "anthropic:"] {
        if let Some(stripped) = name.strip_prefix(prefix) {
            name = stripped;
        }
    }

    if let Some(mapped) = model_map.get(name) {
        return mapped.clone();
    }

    if name.contains("claude") {
        return format!("anthropic/{}", name);
    }
    if name.contains("qwen") {
        return format!("qwen/{}", name);
    }
    if name.contains("deepseek") {
        return format!("deepseek/{}", name);
    }
    if name.contains("o4") {
        return format!("openai/{}", name);
    }
    if name.contains("gemini") {
        return format!("google/{}", name);
    }

    name.to_string()
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    info!("Signal received, shutting down");
}
