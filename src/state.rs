use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// 应用状态
#[derive(Clone)]
pub struct AppState {
    pub model_map: Arc<RwLock<HashMap<String, String>>>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(model_map: Arc<RwLock<HashMap<String, String>>>, client: reqwest::Client) -> Self {
        Self { model_map, client }
    }
}

