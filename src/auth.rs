use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    iat: i64,
    exp: i64,
    scope: String,
}


pub async fn create_signed_jwt(
    email: &str,
    private_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    let claims = Claims {
        iss: email.to_string(),
        aud: "https://www.googleapis.com/oauth2/v4/token".to_string(),
        iat: now,
        exp: now + 600, // 10分钟有效期
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
    };

    // 清理私钥格式
    let cleaned_key = private_key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace('\r', "")
        .replace('\n', "")
        .replace("\\n", "");

    let key = EncodingKey::from_rsa_pem(
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            cleaned_key
        )
        .as_bytes(),
    )?;

    let token = encode(&Header::new(Algorithm::RS256), &claims, &key)?;
    Ok(token)
}

pub async fn exchange_jwt_for_access_token(
    signed_jwt: &str,
    client: &reqwest::Client,
) -> Result<String, Box<dyn std::error::Error>> {
    let auth_url = "https://www.googleapis.com/oauth2/v4/token";
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", signed_jwt),
    ];

    let response = client
        .post(auth_url)
        .form(&params)
        .send()
        .await?;

    let json: serde_json::Value = response.json().await?;
    
    if let Some(access_token) = json.get("access_token").and_then(|v| v.as_str()) {
        Ok(access_token.to_string())
    } else {
        Err(format!("Failed to get access token: {}", json).into())
    }
}

