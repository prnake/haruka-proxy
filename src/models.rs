use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs;

/// 将模型名转换为 Vertex AI 格式
/// 规律：`claude-xxx-20240229` -> `claude-xxx@20240229`
/// 即最后的8位数字日期用 `@` 分隔
pub fn to_vertex_model_name(model_name: &str) -> String {
    // 去掉 vertex: 前缀
    let name = model_name.strip_prefix("vertex:").unwrap_or(model_name);
    
    // 查找最后一个 `-` 后面是否是8位数字（日期格式）
    if let Some(last_dash_pos) = name.rfind('-') {
        let suffix = &name[last_dash_pos + 1..];
        // 检查是否是8位数字（YYYYMMDD格式）
        if suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_digit()) {
            let prefix = &name[..last_dash_pos];
            return format!("{}@{}", prefix, suffix);
        }
    }
    
    // 无法识别的格式，原样返回
    name.to_string()
}

/// 根据模型名确定默认区域
/// haiku 模型使用 global，其他使用 us-east5
pub fn get_vertex_region(model_name: &str) -> String {
    let name = model_name.strip_prefix("vertex:").unwrap_or(model_name);
    
    if name.contains("haiku") {
        "global".to_string()
    } else {
        "us-east5".to_string()
    }
}

/// 检查是否是支持的 Vertex AI 模型
/// 支持所有 claude 模型
pub fn is_vertex_model(model_name: &str) -> bool {
    let name = model_name.strip_prefix("vertex:").unwrap_or(model_name);
    name.starts_with("claude")
}

// 初始化为 models.json 或空（用于 OpenRouter）
pub static INITIAL_MODEL_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    fs::read_to_string("models.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default()
});

pub fn handle_model_name(model_name: &str, model_map: &HashMap<String, String>) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_vertex_model_name() {
        assert_eq!(to_vertex_model_name("claude-3-sonnet-20240229"), "claude-3-sonnet@20240229");
        assert_eq!(to_vertex_model_name("claude-3-7-sonnet-20250219"), "claude-3-7-sonnet@20250219");
        assert_eq!(to_vertex_model_name("claude-sonnet-4-20250514"), "claude-sonnet-4@20250514");
        assert_eq!(to_vertex_model_name("claude-haiku-4-5-20251001"), "claude-haiku-4-5@20251001");
        assert_eq!(to_vertex_model_name("vertex:claude-3-opus-20240229"), "claude-3-opus@20240229");
    }

    #[test]
    fn test_get_vertex_region() {
        assert_eq!(get_vertex_region("claude-haiku-4-5-20251001"), "global");
        assert_eq!(get_vertex_region("claude-3-haiku-20240307"), "global");
        assert_eq!(get_vertex_region("claude-3-7-sonnet-20250219"), "us-east5");
        assert_eq!(get_vertex_region("claude-sonnet-4-20250514"), "us-east5");
    }
}
