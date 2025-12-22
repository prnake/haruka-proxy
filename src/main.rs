mod auth;
mod aws_sign;
mod config;
mod handlers;
mod models;
mod routes;
mod state;
mod utils;

use axum::Router;
use models::INITIAL_MODEL_MAP;
use routes::{bedrock, openrouter, vertex};
use state::AppState;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    sync::RwLock,
    time::{sleep, Duration},
};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // 使用环境变量 RUST_LOG，如果没有设置则默认为 info
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    let model_map = Arc::new(RwLock::new(INITIAL_MODEL_MAP.clone()));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3600)) // 1小时超时
        .pool_max_idle_per_host(10000) // 增大连接池
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(3600))
        .tcp_nodelay(true) // 禁用 Nagle 算法，减少延迟
        .http2_adaptive_window(true) // HTTP/2 自适应窗口
        .build()
        .expect("Failed to build HTTP client");

    let state = AppState::new(model_map.clone(), client.clone());

    // 启动定时任务：每小时拉取最新模型信息
    tokio::spawn(update_models_periodically(model_map.clone(), client.clone()));

    // 合并路由
    let app = Router::new()
        .merge(openrouter::create_router(state.clone()))
        .merge(vertex::create_router(state.clone()))
        .merge(bedrock::create_router(state));

    // 从环境变量读取绑定地址，默认为 0.0.0.0:30033（Docker 友好）
    let bind_host = std::env::var("BIND_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let bind_port: u16 = std::env::var("BIND_PORT")
        .unwrap_or_else(|_| "30033".to_string())
        .parse()
        .unwrap_or(30033);
    
    let addr = SocketAddr::new(
        bind_host.parse().unwrap_or_else(|_| {
            error!("Invalid BIND_HOST: {}, using 0.0.0.0", bind_host);
            "0.0.0.0".parse().unwrap()
        }),
        bind_port,
    );
    
    info!("🚀 Server listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            error!("Server error: {}", e);
            std::process::exit(1);
        });
}

// 定时任务：每小时拉取 https://openrouter.ai/api/v1/models
async fn update_models_periodically(
    model_map: Arc<RwLock<HashMap<String, String>>>,
    client: reqwest::Client,
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
    let json_resp: serde_json::Value = resp.json().await?;

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
        let mut map = model_map.write().await;
        *map = new_map;
        info!("Model map updated from openrouter.ai");
    } else {
        error!("Fetched models list is empty, skip update");
    }
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    info!("Signal received, shutting down");
    std::process::exit(0);
}
