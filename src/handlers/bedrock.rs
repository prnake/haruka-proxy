use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{error, info};

use crate::aws_sign::AwsV4Signer;
use crate::config::{find_bedrock_user, get_bedrock_credential, parse_auth_header, AuthInfo, AwsCredential, Permission};
use crate::state::AppState;
use crate::utils::create_error_response;

/// Bedrock 模型映射
pub static BEDROCK_MODEL_MAPPING: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert("claude-instant-1.2", "anthropic.claude-instant-v1");
    map.insert("claude-2.0", "anthropic.claude-v2");
    map.insert("claude-2.1", "anthropic.claude-v2:1");
    map.insert("claude-3-sonnet-20240229", "anthropic.claude-3-sonnet-20240229-v1:0");
    map.insert("claude-3-opus-20240229", "anthropic.claude-3-opus-20240229-v1:0");
    map.insert("claude-3-haiku-20240307", "anthropic.claude-3-haiku-20240307-v1:0");
    map.insert("claude-3-5-sonnet-20240620", "anthropic.claude-3-5-sonnet-20240620-v1:0");
    map.insert("claude-3-5-sonnet-20241022", "anthropic.claude-3-5-sonnet-20241022-v2:0");
    map.insert("claude-3-5-haiku-20241022", "anthropic.claude-3-5-haiku-20241022-v1:0");
    map.insert("claude-3-7-sonnet-20250219", "anthropic.claude-3-7-sonnet-20250219-v1:0");
    map.insert("claude-sonnet-4-20250514", "anthropic.claude-sonnet-4-20250514-v1:0");
    map.insert("claude-sonnet-4-5-20250929", "global.anthropic.claude-sonnet-4-5-20250929-v1:0");
    map.insert("claude-haiku-4-5-20251001", "global.anthropic.claude-haiku-4-5-20251001-v1:0");
    map.insert("claude-opus-4-20250514", "anthropic.claude-opus-4-20250514-v1:0");
    map.insert("claude-opus-4-1-20250805", "anthropic.claude-opus-4-1-20250805-v1:0");
    map
});

/// 认证结果
struct AuthResult {
    aws_credential: AwsCredential,
    permission: Permission,
    credential_alias: String,
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

/// 处理 Bedrock 消息端点
pub async fn handle_messages_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> impl IntoResponse {
    // 提取 provider 别名
    let provider_alias = extract_provider_alias(&mut payload);

    // 获取 Authorization header
    let auth_header = match headers.get("authorization").or(headers.get("x-api-key")) {
        Some(h) => h.to_str().unwrap_or(""),
        None => {
            return create_error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Missing Authorization header",
            );
        }
    };

    // 解析认证信息
    let auth_info = parse_auth_header(auth_header);
    
    let auth = match auth_info {
        AuthInfo::AwsPassthrough(cred) => {
            // 透传模式默认 admin
            AuthResult {
                aws_credential: cred,
                permission: Permission::Admin,
                credential_alias: "passthrough".to_string(),
            }
        }
        AuthInfo::BearerToken(token) => {
            // 查找用户
            let user = match find_bedrock_user(&token) {
                Some(u) => u,
                None => {
                    return create_error_response(
                        StatusCode::UNAUTHORIZED,
                        "authentication_error",
                        "Invalid API key",
                    );
                }
            };

            // 获取凭证（指定或随机）
            let (alias, cred) = match get_bedrock_credential(provider_alias.as_deref(), &user.allowed_aliases) {
                Some(result) => result,
                None => {
                    let msg = if let Some(p) = provider_alias.as_deref() {
                        format!("Provider '{}' not found or not allowed", p)
                    } else {
                        "No available credentials".to_string()
                    };
                    return create_error_response(
                        StatusCode::UNAUTHORIZED,
                        "authentication_error",
                        &msg,
                    );
                }
            };

            info!(
                "User '{}' using credential '{}' (permission: {:?})",
                user.user_name, alias, user.permission
            );

            AuthResult {
                aws_credential: cred,
                permission: user.permission,
                credential_alias: alias,
            }
        }
    };

    // 检查权限：只有 admin 可以调用 messages 接口
    if auth.permission != Permission::Admin {
        return create_error_response(
            StatusCode::FORBIDDEN,
            "permission_error",
            "Permission denied. This API key can only access count-tokens endpoint.",
        );
    }

    // 获取并处理模型名称
    let model = match payload.get("model").and_then(|m| m.as_str()) {
        Some(m) => {
            // 去掉前缀（如 bedrock:）
            if m.contains(':') {
                m.split(':').nth(1).unwrap_or(m)
            } else {
                m
            }
        }
        None => {
            return create_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "Missing model in request",
            );
        }
    };

    // 查找 Bedrock 模型名称
    let deploy_name = match BEDROCK_MODEL_MAPPING.get(model) {
        Some(name) => *name,
        None => {
            return create_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                &format!("Model `{}` not found", model),
            );
        }
    };

    // 添加区域前缀
    let final_deploy_name = if model == "claude-sonnet-4-5-20250929" || model == "claude-haiku-4-5-20251001" {
        deploy_name.to_string()
    } else if auth.aws_credential.region.starts_with("us-") {
        format!("us.{}", deploy_name)
    } else {
        format!("apac.{}", deploy_name)
    };

    let is_streaming = payload
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // 清理 payload
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("model");
        obj.remove("n");
        obj.remove("stream");
        obj.remove("stream_options");
        obj.insert("anthropic_version".to_string(), json!("bedrock-2023-05-31"));
    }

    // 构建请求 URL
    let url = if is_streaming {
        format!(
            "https://bedrock-runtime.{}.amazonaws.com/model/{}/invoke-with-response-stream",
            auth.aws_credential.region, final_deploy_name
        )
    } else {
        format!(
            "https://bedrock-runtime.{}.amazonaws.com/model/{}/invoke",
            auth.aws_credential.region, final_deploy_name
        )
    };

    info!(
        "Bedrock request: model={}, region={}, credential={}",
        final_deploy_name, auth.aws_credential.region, auth.credential_alias
    );

    // 序列化请求体
    let body_bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize request body: {}", e);
            return create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "Failed to serialize request",
            );
        }
    };

    // AWS V4 签名
    let signer = AwsV4Signer::new(
        &auth.aws_credential.access_key_id,
        &auth.aws_credential.secret_access_key,
        &auth.aws_credential.region,
        "bedrock",
    );

    let mut request_headers = std::collections::BTreeMap::new();
    request_headers.insert("content-type".to_string(), "application/json".to_string());
    
    let signed_headers = signer.sign_request("POST", &url, &request_headers, &body_bytes);

    // 构建请求
    let mut request_builder = state.client.post(&url);
    
    for (key, value) in &signed_headers {
        request_builder = request_builder.header(key, value);
    }
    request_builder = request_builder.header("content-type", "application/json");
    request_builder = request_builder.body(body_bytes);

    let response = match request_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to send request to Bedrock: {}", e);
            return create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "api_error",
                "Failed to connect to Bedrock",
            );
        }
    };

    let status = response.status();

    // 处理流式响应
    if is_streaming {
        let stream = response.bytes_stream();
        Response::builder()
            .status(status)
            .header("Content-Type", "text/event-stream")
            .header("Access-Control-Allow-Origin", "*")
            .header("Cache-Control", "no-cache")
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
