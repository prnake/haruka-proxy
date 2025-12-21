use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use tracing::{error, info};

use crate::auth::{create_signed_jwt, exchange_jwt_for_access_token};
use crate::config::{find_vertex_user, get_vertex_credential, GcpCredential, Permission};
use crate::models::{get_vertex_region, is_vertex_model, to_vertex_model_name};
use crate::state::AppState;
use crate::utils::create_error_response;

/// 认证结果
struct AuthResult {
    access_token: String,
    override_region: String,
    gcp_credentials: GcpCredential,
    permission: Permission,
    credential_alias: String,
}

/// 获取认证信息和 GCP 凭证
async fn get_auth_and_credentials(
    state: &AppState,
    headers: &HeaderMap,
    provider_alias: Option<&str>,
) -> Result<AuthResult, Response> {
    // 获取 Authorization header
    let auth_header = match headers.get("authorization").or(headers.get("x-api-key")) {
        Some(h) => h.to_str().unwrap_or(""),
        None => {
            return Err(create_error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Missing Authorization header",
            ));
        }
    };

    // 提取 Bearer token
    let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);
    
    // 解析 token，支持 `key;region=xxx` 格式
    let (auth_token, override_region) = if token.contains(';') {
        let parts: Vec<&str> = token.splitn(2, ';').collect();
        let mut region = String::new();
        if parts.len() > 1 {
            for part in parts[1].split(';') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "region" {
                        region = v.to_string();
                    }
                }
            }
        }
        (parts[0].to_string(), region)
    } else {
        (token.to_string(), String::new())
    };

    // 查找用户
    let user = match find_vertex_user(&auth_token) {
        Some(u) => u,
        None => {
            return Err(create_error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Invalid API key",
            ));
        }
    };

    // 获取凭证（指定或随机）
    let (alias, gcp_credentials) = match get_vertex_credential(provider_alias, &user.allowed_aliases) {
        Some(result) => result,
        None => {
            let msg = if let Some(p) = provider_alias {
                format!("Provider '{}' not found or not allowed", p)
            } else {
                "No available credentials".to_string()
            };
            return Err(create_error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                &msg,
            ));
        }
    };

    info!(
        "User '{}' using credential '{}' (permission: {:?})",
        user.user_name, alias, user.permission
    );

    // 创建 JWT 并交换访问令牌
    let signed_jwt = match create_signed_jwt(&gcp_credentials.client_email, &gcp_credentials.private_key).await {
        Ok(jwt) => jwt,
        Err(e) => {
            error!("Failed to create JWT: {}", e);
            return Err(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "invalid authentication credentials",
            ));
        }
    };

    let access_token = match exchange_jwt_for_access_token(&signed_jwt, &state.client).await {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to exchange JWT for access token: {}", e);
            return Err(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "invalid authentication credentials",
            ));
        }
    };

    Ok(AuthResult {
        access_token,
        override_region,
        gcp_credentials,
        permission: user.permission,
        credential_alias: alias,
    })
}

/// 从请求 payload 中提取 provider 别名
fn extract_provider_alias(payload: &mut Value) -> Option<String> {
    if let Some(obj) = payload.as_object_mut() {
        if let Some(provider) = obj.remove("provider") {
            return provider.as_str().map(|s| s.to_string());
        }
    }
    None
}

/// 处理消息端点
pub async fn handle_messages_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> impl IntoResponse {
    // 提取 provider 别名
    let provider_alias = extract_provider_alias(&mut payload);

    // 获取认证信息
    let auth = match get_auth_and_credentials(&state, &headers, provider_alias.as_deref()).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    // 检查权限：只有 admin 可以调用 messages 接口
    if auth.permission != Permission::Admin {
        return create_error_response(
            StatusCode::FORBIDDEN,
            "permission_error",
            "Permission denied. This API key can only access count-tokens endpoint.",
        );
    }

    // 验证 Anthropic 版本
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");

    if anthropic_version != "2023-06-01" {
        return create_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "API version not supported",
        );
    }

    // 处理 payload
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("n");
        obj.insert("anthropic_version".to_string(), json!("vertex-2023-10-16"));
    }

    // 获取模型名
    let model_name = payload
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    // 验证模型
    if model_name.is_empty() {
        return create_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "Missing model in the request payload.",
        );
    }
    if !is_vertex_model(&model_name) {
        return create_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("Model `{}` not supported.", model_name),
        );
    }

    // 处理 anthropic_beta
    let mut anthropic_beta = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if let Some(beta) = payload.get("anthropic_beta").or_else(|| payload.get("anthropic-beta")) {
        if let Some(beta_array) = beta.as_array() {
            anthropic_beta = beta_array
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",");
        }
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("anthropic_beta");
            obj.remove("anthropic-beta");
        }
    }

    let stream = payload
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if let Some(obj) = payload.as_object_mut() {
        obj.remove("stream_options");
    }

    // 确定区域
    let region = if !auth.override_region.is_empty() {
        auth.override_region
    } else {
        get_vertex_region(&model_name)
    };

    // 转换模型名为 Vertex 格式
    let vertex_model_name = to_vertex_model_name(&model_name);

    // 删除 model 字段（在 URL 中传递）
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("model");
    }

    // 构建 URL
    let url = format!(
        "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:streamRawPredict",
        region, auth.gcp_credentials.project_id, region, vertex_model_name
    );

    info!(
        "Vertex AI request: model={}, region={}, credential={}",
        vertex_model_name, region, auth.credential_alias
    );

    // 发送请求
    let mut request_builder = state
        .client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", auth.access_token))
        .header("Anthropic-Version", anthropic_version)
        .json(&payload);

    if !anthropic_beta.is_empty() {
        request_builder = request_builder.header("Anthropic-Beta", anthropic_beta);
    }

    let response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to send request to Vertex AI: {}", e);
            return create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "Server Error",
            );
        }
    };

    let status = response.status();

    // 处理流式响应
    if stream {
        let stream = response.bytes_stream();
        Response::builder()
            .status(status)
            .header("Content-Type", "text/event-stream")
            .header("Access-Control-Allow-Origin", "*")
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| {
                create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "api_error",
                    "Server Error",
                )
            })
    } else {
        // 处理非流式响应
        match response.text().await {
            Ok(data) => {
                let mut response_data: Value = match serde_json::from_str(&data) {
                    Ok(json) => json,
                    Err(_) => {
                        return Response::builder()
                            .status(status)
                            .header("Content-Type", "application/json")
                            .header("Access-Control-Allow-Origin", "*")
                            .body(Body::from(data))
                            .unwrap();
                    }
                };

                // 转换 usage 格式
                if let Some(usage) = response_data.get_mut("usage") {
                    if let Some(usage_obj) = usage.as_object_mut() {
                        if let (Some(input_tokens), Some(output_tokens)) = (
                            usage_obj.get("input_tokens").and_then(|v| v.as_u64()),
                            usage_obj.get("output_tokens").and_then(|v| v.as_u64()),
                        ) {
                            usage_obj.insert("prompt_tokens".to_string(), json!(input_tokens));
                            usage_obj.insert("completion_tokens".to_string(), json!(output_tokens));
                            usage_obj.insert("total_tokens".to_string(), json!(input_tokens + output_tokens));
                        }
                    }
                }

                Response::builder()
                    .status(status)
                    .header("Content-Type", "application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(Body::from(serde_json::to_string(&response_data).unwrap_or_default()))
                    .unwrap()
            }
            Err(e) => {
                error!("Failed to read response: {}", e);
                create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "api_error",
                    "Server Error",
                )
            }
        }
    }
}

/// 处理 count tokens 端点
pub async fn handle_count_tokens_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> impl IntoResponse {
    // 提取 provider 别名
    let provider_alias = extract_provider_alias(&mut payload);

    // 获取认证信息（admin 和 count_token 权限都可以访问）
    let auth = match get_auth_and_credentials(&state, &headers, provider_alias.as_deref()).await {
        Ok(v) => v,
        Err(e) => return e,
    };

    // count_token 和 admin 权限都可以调用此接口

    // 验证 Anthropic 版本
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("2023-06-01");

    if anthropic_version != "2023-06-01" {
        return create_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "API version not supported",
        );
    }

    // 处理 payload
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("n");
        obj.insert("anthropic_version".to_string(), json!("vertex-2023-10-16"));
    }

    // 获取模型名
    let model_name = payload
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    if model_name.is_empty() {
        return create_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "Missing model in the request payload.",
        );
    }

    // 确定区域
    let region = if !auth.override_region.is_empty() {
        auth.override_region
    } else {
        get_vertex_region(&model_name)
    };

    // 转换模型名为 Vertex 格式，更新 payload
    let vertex_model_name = to_vertex_model_name(&model_name);
    payload["model"] = json!(vertex_model_name);

    // 构建 URL
    let url = format!(
        "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/anthropic/models/count-tokens:rawPredict",
        region, auth.gcp_credentials.project_id, region
    );

    info!(
        "Vertex AI count-tokens request: model={}, region={}, credential={}",
        vertex_model_name, region, auth.credential_alias
    );

    // 发送请求
    let request_builder = state
        .client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", auth.access_token))
        .header("Anthropic-Version", anthropic_version)
        .json(&payload);

    let response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to send request to Vertex AI: {}", e);
            return create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "Server Error",
            );
        }
    };

    let status = response.status();

    // 处理响应
    match response.text().await {
        Ok(data) => {
            Response::builder()
                .status(status)
                .header("Content-Type", "application/json")
                .header("Access-Control-Allow-Origin", "*")
                .body(Body::from(data))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to read response: {}", e);
            create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "Server Error",
            )
        }
    }
}
