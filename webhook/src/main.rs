use std::env;
use warp::Filter;
use serde_json::Value;
use openssl::rsa::Rsa;
use jwt::{SignWithKey, VerifyWithKey};
use chrono::{Utc, Duration};
use octocrab::{Octocrab, models::AppId};
use dotenvy::dotenv;
use jsonwebtoken::EncodingKey;
use std::fs;
#[tokio::main]
async fn main() {
    dotenv().ok();
    // Read environment variables
    let github_app_id = env::var("GITHUB_APP_ID").expect("Missing GITHUB_APP_ID");
    let github_private_key = env::var("GITHUB_PRIVATE_KEY").expect("Missing GITHUB_PRIVATE_KEY");
    let webhook_secret = env::var("GITHUB_WEBHOOK_SECRET").expect("Missing GITHUB_WEBHOOK_SECRET");

    // Create RSA private key from the provided environment variable
    let rsa_key = EncodingKey::from_rsa_pem(github_private_key.as_bytes()).expect("Failed to load private key");
    // Create Octocrab instance for GitHub App authentication
    let octocrab = Octocrab::builder()
        .app(AppId::from(github_app_id.parse::<u64>().unwrap()), rsa_key)
        .build()
        .expect("Failed to create Octocrab instance");

    // Warp filter for event handling
    let event_handler = warp::path!("P4ULefIpD7wLKY0V")
        .and(warp::post())
        .and(warp::header::<String>("X-Hub-Signature-256"))
        .and(warp::body::json())
        .map(move |signature: String, payload: Value| {
            // Verify the signature
            let our_signature = format!("sha256={}", payload);
            if !openssl::memcmp::eq(our_signature.as_bytes(), signature.as_bytes()) {
                return warp::http::StatusCode::UNAUTHORIZED;
            }

            
            // Handle events and perform actions
            // ... Your code here ...
            let file_path = "testtt.txt";
            match fs::write(file_path, signature.clone().as_bytes()) {
                Ok(_) => println!("成功写入文件."),
                Err(e) => eprintln!("写入文件时发生错误: {}", e),
            }


            warp::http::StatusCode::OK
        });

    warp::serve(event_handler)
        .run(([0, 0, 0, 0], 3000))
        .await;
}