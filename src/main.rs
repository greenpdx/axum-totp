
use axum::Router;
use axum::http::Method;
use std::time::Duration;

use axum_topo::{
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

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);

    let state = AppState::init();

    // Spawn background task to cleanup expired sessions
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired_sessions();
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
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}

async fn init_router(state: AppState, _cors: CorsLayer) -> Router {
    let auth = auth_routes(state);

    // Serve static files from the frontend dist folder
    let serve_dir = ServeDir::new("frontend/dist")
        .not_found_service(ServeFile::new("frontend/dist/index.html"));

    Router::new()
    .nest("/auth", auth)
    .fallback_service(serve_dir)
    .layer(CorsLayer::permissive())
    .layer(TraceLayer::new_for_http())
}

