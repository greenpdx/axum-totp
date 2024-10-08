
use axum::{Router, routing::get};
use axum::http::Method;
mod services;
mod models;
mod response;

use crate::{
    models::AppState,
    services::auth_routes,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer
};

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);
    
    let state = AppState::init();

    let app = init_router(state, cors).await;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    println!("Hello, world!");
    axum::serve(listener, app).await.unwrap();
}

async fn hello_world() -> &'static str {
    "Hello world!"
}

async fn init_router(state: AppState, _cors: CorsLayer) -> Router {
    let auth = auth_routes(state);
    Router::new()
    .route("/", get(hello_world))
    .nest("/auth", auth)
    .layer(CorsLayer::permissive())
    .layer(TraceLayer::new_for_http())

}

