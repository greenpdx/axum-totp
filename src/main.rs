use axum::{middleware, Router};
use axum::http::Method;
use std::net::SocketAddr;
use std::time::Duration;

use axum_totp::{
    acl::auth_middleware,
    models::AppState,
    services::auth_routes,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    services::{ServeDir, ServeFile},
};

// Cleanup interval for expired sessions (5 minutes)
const SESSION_CLEANUP_INTERVAL_SECS: u64 = 300;

// Database URL - defaults to local SQLite file
const DATABASE_URL: &str = "sqlite:./data.db?mode=rwc";

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any)
        .allow_headers(Any);

    // Initialize database
    let state = match AppState::init(DATABASE_URL).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize database: {}", e);
            std::process::exit(1);
        }
    };

    // Spawn background task to cleanup expired sessions
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_state.cleanup_expired_sessions().await {
                eprintln!("Session cleanup error: {}", e);
            }
        }
    });

    let app = init_router(state, cors).await;

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8000").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to port 8000: {}", e);
            std::process::exit(1);
        }
    };
    println!("Server running on http://0.0.0.0:8000");

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>()
    ).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}

async fn init_router(state: AppState, _cors: CorsLayer) -> Router {
    let auth = auth_routes(state.clone());

    // Serve static files from the frontend dist folder
    let serve_dir = ServeDir::new("frontend/dist")
        .not_found_service(ServeFile::new("frontend/dist/index.html"));

    Router::new()
        .nest("/auth", auth)
        .fallback_service(serve_dir)
        // Auth middleware extracts user ID and role from session token header
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
