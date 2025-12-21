use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use chrono::Utc;

type HmacSha256 = Hmac<Sha256>;

/// AWS V4 签名器
pub struct AwsV4Signer {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    service: String,
}

impl AwsV4Signer {
    pub fn new(access_key_id: &str, secret_access_key: &str, region: &str, service: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            region: region.to_string(),
            service: service.to_string(),
        }
    }

    /// 签名请求，返回需要添加的 headers
    pub fn sign_request(
        &self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> BTreeMap<String, String> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let parsed_url = url::Url::parse(url).unwrap();
        let host = parsed_url.host_str().unwrap_or("");
        let path = parsed_url.path();
        let query = parsed_url.query().unwrap_or("");

        // 构建 canonical headers
        let mut canonical_headers = BTreeMap::new();
        canonical_headers.insert("host".to_string(), host.to_string());
        canonical_headers.insert("x-amz-date".to_string(), amz_date.clone());
        
        for (key, value) in headers {
            let lower_key = key.to_lowercase();
            if !["authorization", "content-length", "user-agent", "expect", "connection"].contains(&lower_key.as_str()) {
                canonical_headers.insert(lower_key, value.clone());
            }
        }

        let signed_headers: Vec<&String> = canonical_headers.keys().collect();
        let signed_headers_str = signed_headers
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_headers_str = canonical_headers
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v.trim()))
            .collect::<Vec<_>>()
            .join("\n");

        // 计算 payload hash
        let payload_hash = hex::encode(Sha256::digest(body));

        // 构建 canonical request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n\n{}\n{}",
            method,
            path,
            query,
            canonical_headers_str,
            signed_headers_str,
            payload_hash
        );

        // 构建 string to sign
        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, self.region, self.service);
        let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm,
            amz_date,
            credential_scope,
            canonical_request_hash
        );

        // 计算签名
        let signing_key = self.get_signature_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        // 构建 Authorization header
        let authorization = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm,
            self.access_key_id,
            credential_scope,
            signed_headers_str,
            signature
        );

        let mut result = BTreeMap::new();
        result.insert("Authorization".to_string(), authorization);
        result.insert("x-amz-date".to_string(), amz_date);
        result.insert("x-amz-content-sha256".to_string(), payload_hash);
        
        result
    }

    fn get_signature_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

