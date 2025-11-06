use axum::{
    body::Body,
    extract::{State, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
    extract::DefaultBodyLimit,
};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::RwLock, time::{Duration, sleep}};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info};

// 应用状态
#[derive(Clone)]
struct AppState {
    model_map: Arc<RwLock<HashMap<String, String>>>,
    client: reqwest::Client,
}

// 初始化为 models.json 或空
static INITIAL_MODEL_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    fs::read_to_string("models.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
});

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let model_map = Arc::new(RwLock::new(INITIAL_MODEL_MAP.clone()));
    let client = reqwest::Client::new();
    let state = AppState {
        model_map: model_map.clone(),
        client: client.clone(),
    };

    // 启动定时任务：每小时拉取最新模型信息
    tokio::spawn(update_models_periodically(model_map.clone(), client.clone()));

    let app = Router::new()
        .route("/v1/chat/completions", post(handle_post))
        .route("/msgs_forward/{domain}/v1/chat/completions", post(handle_msgs_forward))
        .route("/chat_forward/{domain_type}/v1/chat/completions", post(handle_chat_completions_forward))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 30033));
    info!("🚀 Server listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

// 定时任务：每小时拉 https://openrouter.ai/api/v1/models
async fn update_models_periodically(
    model_map: Arc<RwLock<HashMap<String, String>>>,
    client: reqwest::Client
) {
    loop {
        if let Err(e) = update_models(&model_map, &client).await {
            error!("Failed to update models: {}", e);
        }
        sleep(Duration::from_secs(60 * 60)).await; // 1小时
    }
}

// 调用openrouter API并更新HashMap
async fn update_models(
    model_map: &Arc<RwLock<HashMap<String, String>>>,
    client: &reqwest::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.get("https://openrouter.ai/api/v1/models").send().await?;
    let json_resp: Value = resp.json().await?;

    // 假设模型结构为 { "data": [ {"id": "...", ...}, ... ] }
    let mut new_map = HashMap::new();
    if let Some(list) = json_resp.get("data").and_then(|d| d.as_array()) {
        for item in list {
            if let Some(id_full) = item.get("id").and_then(|id| id.as_str()) {
                let id = id_full.split('/').nth(1).unwrap_or(id_full);
                new_map.insert(id.to_string(), id_full.to_string());
            }
        }
    }

    // 若拉到有效数据再替换原map
    if !new_map.is_empty() {
        let mut map: tokio::sync::RwLockWriteGuard<'_, HashMap<String, String>> = model_map.write().await;
        *map = new_map;
        info!("Model map updated from openrouter.ai");
    } else {
        error!("Fetched models list is empty, skip update");
    }
    Ok(())
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

    let model_map_guard = state.model_map.read().await;

    if let Some(model_val) = body.get("model").and_then(|m| m.as_str()) {
        let mapped_model = handle_model_name(model_val, &*model_map_guard);
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

    if let Some(pos) = name.find(':') {
        name = &name[..pos];
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

async fn handle_chat_completions_forward(
    State(state): State<AppState>,
    Path(domain_type): Path<String>,
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

    // Strip the first colon and its prefix from model for this route if present
    if let Some(model) = body.get("model").and_then(|m| m.as_str()) {
        if let Some(pos) = model.find(':') {
            let new_model = &model[(pos+1)..];
            body["model"] = json!(new_model);
        }
    }

    let mut forward_headers = HeaderMap::new();
    forward_headers.insert("content-type", "application/json".parse().unwrap());
    if let Some(auth) = headers.get("authorization") {
        forward_headers.insert("authorization", auth.clone());
    }

    let target_url = match domain_type.as_str() {
        "minimax" => "https://api.minimaxi.com/v1/text/chatcompletion_v2",
        _ => return (StatusCode::BAD_REQUEST, "Unsupported domain type").into_response(),
    };

    let res = state.client
        .post(target_url)
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
            error!("Forward request to {} failed: {}", domain_type, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error forwarding to {}: {}", domain_type, err),
            )
                .into_response()
        }
    }
}

async fn handle_msgs_forward(
    State(state): State<AppState>,
    Path(domain): Path<String>,
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

    // Strip the first colon and its prefix from model for this route if present
    if let Some(model) = body.get("model").and_then(|m| m.as_str()) {
        if let Some(pos) = model.find(':') {
            let new_model = &model[(pos+1)..];
            body["model"] = json!(new_model);
        }
    }

    let mut forward_headers = HeaderMap::new();
    forward_headers.insert("content-type", "application/json".parse().unwrap());
    if let Some(auth) = headers.get("authorization") {
        // forward_headers.insert("authorization", auth.clone());
        if let Ok(auth_str) = auth.to_str() {
            let token = auth_str.strip_prefix("Bearer ").unwrap_or(auth_str);
            forward_headers.insert("x-api-key", token.parse().unwrap());
        }
    }
    if let Some(auth) = headers.get("x-api-key") {
        forward_headers.insert("x-api-key", auth.clone());
    }

    // for (key, value) in headers.iter() {
    //     // Skip headers that are already handled explicitly above
    //     let key_str = key.as_str().to_ascii_lowercase();
    //     if key_str == "content-type" || key_str == "authorization" || key_str == "x-api-key" {
    //         continue;
    //     }
    //     forward_headers.append(key, value.clone());
    // }

    // 检查 body 中是否含有 anthropic-beta 或 anthropic_beta
    if let Some(beta_val) = body.get("anthropic-beta").or_else(|| body.get("anthropic_beta")) {
        if beta_val.is_array() {
            let arr = beta_val.as_array().unwrap();
            let vals: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let beta_str = vals.join(",");
            forward_headers.insert("anthropic-beta", beta_str.parse().unwrap());
        } else if beta_val.is_string() {
            let beta_str = beta_val.as_str().unwrap();
            forward_headers.insert("anthropic-beta", beta_str.parse().unwrap());
        }
    }

    // anthropic-version header 检查，不存在则设置为 2023-06-01
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");

    let anthropic_beta = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    forward_headers.insert("anthropic-version", anthropic_version.to_string().parse().unwrap());
    if !anthropic_beta.is_empty() {
        forward_headers.insert("anthropic-beta", anthropic_beta.to_string().parse().unwrap());
    }

    // 如果 anthropic-version 存在且不是 2023-06-01，则返回 400
    if anthropic_version != "2023-06-01" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": {
                    "type": "invalid_request_error",
                    "message": "API version not supported"
                }
            })),
        ).into_response();
    }

    let target_url = match domain.as_str() {
        "minimax" => "https://api.minimaxi.com/anthropic/v1/messages".to_string(),
        _ => format!("https://{}/v1/messages", domain),
    };

    if body.get("n").is_some() {
        body.as_object_mut().map(|m| m.remove("n"));
    }

    let res = state.client
        .post(&target_url)
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
            error!("Forward request to {} failed: {}", domain, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error forwarding to {}: {}", domain, err),
            )
                .into_response()
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    info!("Signal received, shutting down");
    std::process::exit(0);
}