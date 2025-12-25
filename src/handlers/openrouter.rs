use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::error;

use crate::models::handle_model_name;
use crate::state::AppState;

pub async fn handle_post(
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

    let model_val_opt = body.get("model").and_then(|m| m.as_str()).map(|s| s.to_string());
    if let Some(model_val) = model_val_opt.as_deref() {
        let mapped_model = handle_model_name(model_val, &*model_map_guard);
        body["model"] = json!(mapped_model);
        if model_val.ends_with(":z-ai") {
            body["provider"] = json!({ "only": ["z-ai"], "allow_fallbacks": false });
        }
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

pub async fn handle_messages(
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

    // 仅替换模型名称
    let model_map_guard = state.model_map.read().await;

    let model_val_opt = body.get("model").and_then(|m| m.as_str()).map(|s| s.to_string());
    if let Some(model_val) = model_val_opt.as_deref() {
        let mapped_model = handle_model_name(model_val, &*model_map_guard);
        body["model"] = json!(mapped_model);
    } else {
        return (StatusCode::BAD_REQUEST, "Missing model").into_response();
    }

    let mut forward_headers = HeaderMap::new();
    forward_headers.insert("content-type", "application/json".parse().unwrap());
    if let Some(auth) = headers.get("authorization") {
        let value = format!("Bearer {}", auth.to_str().unwrap_or_default());
        forward_headers.insert("authorization", value.parse().unwrap());
    } else if let Some(x_api_key) = headers.get("x-api-key") {
        let value = format!("Bearer {}", x_api_key.to_str().unwrap_or_default());
        forward_headers.insert("authorization", value.parse().unwrap());
    }

    let res = state
        .client
        .post("https://openrouter.ai/api/v1/messages")
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

pub async fn handle_chat_completions_forward(
    State(state): State<AppState>,
    axum::extract::Path(domain_type): axum::extract::Path<String>,
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
            let new_model = &model[(pos + 1)..];
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

    let res = state
        .client
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

pub async fn handle_msgs_forward(
    State(state): State<AppState>,
    axum::extract::Path(domain): axum::extract::Path<String>,
    Query(query): Query<HashMap<String, String>>,
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
            let new_model = &model[(pos + 1)..];
            body["model"] = json!(new_model);
        }
    }

    // 检查 body 中是否有 provider 字段
    let provider = body.get("provider").and_then(|p| p.as_str());

    let mut forward_headers = HeaderMap::new();
    forward_headers.insert("content-type", "application/json".parse().unwrap());
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            let mut token = auth_str.strip_prefix("Bearer ").unwrap_or(auth_str).to_string();
            if let Some(provider_val) = provider {
                token = format!("{}-{}", token, provider_val);
            }
            forward_headers.insert("x-api-key", token.parse().unwrap());
        }
    }
    if let Some(auth) = headers.get("x-api-key") {
        let mut token = auth.to_str().unwrap_or("").to_string();
        if let Some(provider_val) = provider {
            token = format!("{}-{}", token, provider_val);
        }
        forward_headers.insert("x-api-key", token.parse().unwrap());
    }

    // anthropic-version header 检查，不存在则设置为 2023-06-01
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");

    let anthropic_beta = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            body.get("anthropic-beta")
                .or_else(|| body.get("anthropic_beta"))
                .and_then(|v| v.as_str())
        })
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
        )
            .into_response();
    }

    let target_url = match domain.as_str() {
        "minimax" => "https://api.minimaxi.com/anthropic/v1/messages".to_string(),
        _ => format!("https://{}/v1/messages", domain),
    };

    if let Some(obj) = body.as_object_mut() {
        obj.remove("n");
        obj.remove("anthropic-beta");
        obj.remove("anthropic_beta");
        obj.remove("provider");
    }

    // 拼接 query string
    let url_with_query = if query.is_empty() {
        target_url
    } else {
        let qs = serde_urlencoded::to_string(&query).unwrap_or_default();
        format!("{}?{}", target_url, qs)
    };

    let res = state
        .client
        .post(&url_with_query)
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

pub async fn handle_gemini_forward(
    State(state): State<AppState>,
    axum::extract::Path(domain): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if !headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.starts_with("application/json"))
    {
        return (StatusCode::BAD_REQUEST, "Unsupported content type").into_response();
    }

    // Strip the first colon and its prefix from model for this route if present
    let model = match body.get("model").and_then(|m| m.as_str()) {
        Some(model) => {
            if let Some(pos) = model.find(':') {
                &model[(pos + 1)..]
            } else {
                model
            }
        }
        None => return (StatusCode::BAD_REQUEST, "Missing model").into_response(),
    };

    // 拿 messages[0]["content"]
    let messages: Value = match body
        .get("messages")
        .and_then(|msgs| msgs.as_array())
        .and_then(|msgs_arr| msgs_arr.get(0))
        .and_then(|first_msg| first_msg.get("content"))
        .cloned()
    {
        Some(content) => content,
        None => return (StatusCode::BAD_REQUEST, "Missing `messages[0].content`").into_response(),
    };

    // 构建转发 URL
    let target_url = format!("https://{}/v1beta/models/{}:generateContent", domain, model);

    // 从 header 读取 authorization，去掉 Bearer 前缀
    let mut forward_headers = reqwest::header::HeaderMap::new();
    forward_headers.insert("content-type", "application/json".parse().unwrap());

    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            let access_token = auth_str.strip_prefix("Bearer ").unwrap_or(auth_str);
            forward_headers.insert("x-goog-api-key", access_token.parse().unwrap());
        }
    }

    // 发送请求，body 是 messages
    let res = state
        .client
        .post(&target_url)
        .headers(forward_headers)
        .json(&messages)
        .send()
        .await;

    match res {
        Ok(resp) => {
            let status = resp.status();

            // 使用 bytes 而不是 text，避免 UTF-8 验证开销
            let response_bytes = match resp.bytes().await {
                Ok(bytes) => bytes,
                Err(err) => {
                    error!("Failed to read response from {}: {}", domain, err);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Error reading response: {}", err),
                    )
                        .into_response();
                }
            };

            // 尝试解析 JSON
            match serde_json::from_slice::<Value>(&response_bytes) {
                Ok(data) => {
                    // 提取 usageMetadata
                    let mut response_json = json!({
                        "model": model,
                        "choices": [{
                            "index": 0,
                            "message": data
                        }]
                    });

                    if let Some(usage_metadata) = data.get("usageMetadata") {
                        if let (Some(prompt_tokens), Some(total_tokens)) = (
                            usage_metadata
                                .get("promptTokenCount")
                                .and_then(|v| v.as_u64()),
                            usage_metadata.get("totalTokenCount").and_then(|v| v.as_u64()),
                        ) {
                            let completion_tokens = total_tokens.saturating_sub(prompt_tokens);
                            response_json["usage"] = json!({
                                "prompt_tokens": prompt_tokens,
                                "completion_tokens": completion_tokens,
                                "total_tokens": total_tokens
                            });
                        }
                    }

                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&response_json).unwrap_or_default()))
                        .unwrap()
                }
                Err(_) => {
                    // JSON 解析失败，直接转发原始响应
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(Body::from(response_bytes))
                        .unwrap()
                }
            }
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

