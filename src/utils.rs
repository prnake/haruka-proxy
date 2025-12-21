use axum::{
    http::StatusCode,
    response::Response,
};
use serde_json::json;

pub fn create_error_response(
    status: StatusCode,
    error_type: &str,
    message: &str,
) -> Response {
    let error_object = json!({
        "type": "error",
        "error": {
            "type": error_type,
            "message": message
        }
    });
    
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&error_object).unwrap().into())
        .unwrap()
}

#[allow(dead_code)]
pub fn parse_api_key_and_settings(api_key_and_settings: &str) -> (String, String, String) {
    let mut api_key = String::new();
    let mut api_region = String::new();
    let mut api_gcp_key = "A".to_string();
    
    if api_key_and_settings.contains(';') {
        let parts: Vec<&str> = api_key_and_settings.split(';').collect();
        for part in parts {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "key" => api_key = value.to_string(),
                    "region" => api_region = value.to_string(),
                    "gcp_key" => api_gcp_key = value.to_string(),
                    _ => {}
                }
            }
        }
    } else {
        api_key = api_key_and_settings.to_string();
    }
    
    (api_key, api_region, api_gcp_key)
}

