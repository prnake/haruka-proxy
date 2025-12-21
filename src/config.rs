use once_cell::sync::Lazy;
use rand::prelude::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use tracing::info;

/// 权限类型
#[derive(Clone, Debug, PartialEq)]
pub enum Permission {
    /// 管理员权限，可以调用所有接口
    Admin,
    /// 只能调用 count-tokens 接口
    CountToken,
}

impl Permission {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "count_token" | "count-token" | "counttoken" => Permission::CountToken,
            _ => Permission::Admin, // 默认 admin
        }
    }
}

/// 用户配置
#[derive(Clone, Debug)]
pub struct UserConfig {
    /// 客户端使用的 Bearer token
    pub auth_key: String,
    /// 权限类型
    pub permission: Permission,
    /// 允许使用的凭证别名列表（空表示可使用所有）
    pub allowed_aliases: Vec<String>,
}

/// Vertex AI 的 GCP 凭证
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcpCredential {
    pub client_email: String,
    pub private_key: String,
    pub project_id: String,
}

impl GcpCredential {
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

/// Bedrock 的 AWS 凭证
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AwsCredential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl AwsCredential {
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

/// 解析用户配置格式：`auth_key;权限;alias1,alias2,...`
fn parse_user_config(value: &str) -> Option<UserConfig> {
    let parts: Vec<&str> = value.splitn(3, ';').collect();
    if parts.is_empty() {
        return None;
    }
    
    let auth_key = parts[0].to_string();
    let permission = if parts.len() > 1 {
        Permission::from_str(parts[1])
    } else {
        Permission::Admin
    };
    let allowed_aliases = if parts.len() > 2 && !parts[2].is_empty() {
        parts[2].split(',').map(|s| s.trim().to_string()).collect()
    } else {
        Vec::new() // 空表示可使用所有凭证
    };
    
    Some(UserConfig {
        auth_key,
        permission,
        allowed_aliases,
    })
}

/// 从环境变量加载凭证（前缀_别名=JSON）
fn load_credentials<T, F>(prefix: &str, parser: F) -> HashMap<String, T>
where
    F: Fn(&str) -> Result<T, serde_json::Error>,
{
    let mut credentials = HashMap::new();
    let user_prefix = format!("{}_USER_", prefix.trim_end_matches('_'));
    
    for (key, value) in env::vars() {
        // 跳过用户配置
        if key.starts_with(&user_prefix) {
            continue;
        }
        
        if key.starts_with(prefix) {
            let alias = key.strip_prefix(prefix).unwrap_or(&key).to_string();
            if let Ok(cred) = parser(&value) {
                info!("Loaded credential: {} (alias: {})", key, alias);
                credentials.insert(alias, cred);
            }
        }
    }
    
    credentials
}

/// 从环境变量加载用户配置（前缀_USER_名称=key;权限;aliases）
fn load_users(prefix: &str) -> HashMap<String, UserConfig> {
    let mut users = HashMap::new();
    let user_prefix = format!("{}_USER_", prefix.trim_end_matches('_'));
    
    for (key, value) in env::vars() {
        if key.starts_with(&user_prefix) {
            let name = key.strip_prefix(&user_prefix).unwrap_or(&key).to_string();
            if let Some(config) = parse_user_config(&value) {
                info!(
                    "Loaded user: {} (key: {}..., permission: {:?}, aliases: {:?})",
                    name,
                    &config.auth_key.chars().take(8).collect::<String>(),
                    config.permission,
                    if config.allowed_aliases.is_empty() { vec!["*".to_string()] } else { config.allowed_aliases.clone() }
                );
                users.insert(name, config);
            }
        }
    }
    
    users
}

/// Vertex AI 凭证（前缀：VERTEX_）
pub static VERTEX_CREDENTIALS: Lazy<HashMap<String, GcpCredential>> = Lazy::new(|| {
    load_credentials("VERTEX_", GcpCredential::from_json)
});

/// Vertex AI 用户（前缀：VERTEX_USER_）
pub static VERTEX_USERS: Lazy<HashMap<String, UserConfig>> = Lazy::new(|| {
    load_users("VERTEX_")
});

/// Bedrock 凭证（前缀：BEDROCK_）
pub static BEDROCK_CREDENTIALS: Lazy<HashMap<String, AwsCredential>> = Lazy::new(|| {
    load_credentials("BEDROCK_", AwsCredential::from_json)
});

/// Bedrock 用户（前缀：BEDROCK_USER_）
pub static BEDROCK_USERS: Lazy<HashMap<String, UserConfig>> = Lazy::new(|| {
    load_users("BEDROCK_")
});

/// 查找用户配置结果
pub struct UserLookupResult {
    pub user_name: String,
    pub permission: Permission,
    pub allowed_aliases: Vec<String>,
}

/// 根据 auth_token 查找 Vertex 用户
pub fn find_vertex_user(auth_token: &str) -> Option<UserLookupResult> {
    for (name, config) in VERTEX_USERS.iter() {
        if config.auth_key == auth_token {
            return Some(UserLookupResult {
                user_name: name.clone(),
                permission: config.permission.clone(),
                allowed_aliases: config.allowed_aliases.clone(),
            });
        }
    }
    None
}

/// 根据 auth_token 查找 Bedrock 用户
pub fn find_bedrock_user(auth_token: &str) -> Option<UserLookupResult> {
    for (name, config) in BEDROCK_USERS.iter() {
        if config.auth_key == auth_token {
            return Some(UserLookupResult {
                user_name: name.clone(),
                permission: config.permission.clone(),
                allowed_aliases: config.allowed_aliases.clone(),
            });
        }
    }
    None
}

/// 获取 Vertex 凭证（指定别名或随机选择）
pub fn get_vertex_credential(alias: Option<&str>, allowed_aliases: &[String]) -> Option<(String, GcpCredential)> {
    let credentials = &*VERTEX_CREDENTIALS;
    
    if credentials.is_empty() {
        return None;
    }
    
    // 过滤出允许的凭证
    let available: Vec<(&String, &GcpCredential)> = if allowed_aliases.is_empty() {
        // 允许所有
        credentials.iter().collect()
    } else {
        credentials
            .iter()
            .filter(|(k, _)| allowed_aliases.contains(k))
            .collect()
    };
    
    if available.is_empty() {
        return None;
    }
    
    if let Some(target_alias) = alias {
        // 指定了别名，查找对应凭证
        available
            .iter()
            .find(|(k, _)| *k == target_alias)
            .map(|(k, v)| ((*k).clone(), (*v).clone()))
    } else {
        // 随机选择
        let mut rng = rand::rng();
        available
            .choose(&mut rng)
            .map(|(k, v)| ((*k).clone(), (*v).clone()))
    }
}

/// 获取 Bedrock 凭证（指定别名或随机选择）
pub fn get_bedrock_credential(alias: Option<&str>, allowed_aliases: &[String]) -> Option<(String, AwsCredential)> {
    let credentials = &*BEDROCK_CREDENTIALS;
    
    if credentials.is_empty() {
        return None;
    }
    
    // 过滤出允许的凭证
    let available: Vec<(&String, &AwsCredential)> = if allowed_aliases.is_empty() {
        // 允许所有
        credentials.iter().collect()
    } else {
        credentials
            .iter()
            .filter(|(k, _)| allowed_aliases.contains(k))
            .collect()
    };
    
    if available.is_empty() {
        return None;
    }
    
    if let Some(target_alias) = alias {
        // 指定了别名，查找对应凭证
        available
            .iter()
            .find(|(k, _)| *k == target_alias)
            .map(|(k, v)| ((*k).clone(), (*v).clone()))
    } else {
        // 随机选择
        let mut rng = rand::rng();
        available
            .choose(&mut rng)
            .map(|(k, v)| ((*k).clone(), (*v).clone()))
    }
}

/// 解析 Authorization header，支持以下格式：
/// - `Bearer <token>` - 用于 Vertex/Bedrock 鉴权
/// - `region=xxx;accessKeyId=xxx;secretAccessKey=xxx` - 直接传递 AWS 凭证（透传模式）
pub fn parse_auth_header(auth_header: &str) -> AuthInfo {
    let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);
    
    // 检查是否是 AWS 透传格式
    if token.contains("region=") && token.contains("accessKeyId=") {
        if let Some(aws_cred) = parse_aws_passthrough(token) {
            return AuthInfo::AwsPassthrough(aws_cred);
        }
    }
    
    AuthInfo::BearerToken(token.to_string())
}

/// 解析 AWS 透传格式：`region=xxx;accessKeyId=xxx;secretAccessKey=xxx`
fn parse_aws_passthrough(token: &str) -> Option<AwsCredential> {
    let mut region = None;
    let mut access_key_id = None;
    let mut secret_access_key = None;
    
    for part in token.split(';') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "region" => region = Some(value.to_string()),
                "accessKeyId" => access_key_id = Some(value.to_string()),
                "secretAccessKey" => secret_access_key = Some(value.to_string()),
                _ => {}
            }
        }
    }
    
    match (region, access_key_id, secret_access_key) {
        (Some(r), Some(a), Some(s)) => Some(AwsCredential {
            region: r,
            access_key_id: a,
            secret_access_key: s,
        }),
        _ => None,
    }
}

#[derive(Debug)]
pub enum AuthInfo {
    BearerToken(String),
    AwsPassthrough(AwsCredential),
}
