
use axum::{
    Router,
    Extension,
    http::Method,
    routing::get,
};
use models::ReqState;
mod services;
mod models;
mod response;
mod db;

use crate::{
    models::AppState,
    services::auth_routes,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer
};
use std::sync::Arc;

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
    let reqstate = Arc::new(ReqState { test: "BOB".to_string()});

    Router::new()
    .route("/", get(hello_world))
    .nest("/auth", auth)
    .layer(Extension(reqstate))
    .layer(CorsLayer::permissive())
    .layer(TraceLayer::new_for_http())

}

#[cfg(test)]
mod test {
    use super::*;
    use axum_test::TestServer;
    use crate::{
        models::{
            AppState, DisableOTPSchema, GenerateOTPSchema, User, UserLoginSchema, UserRegisterSchema,
            VerifyOTPSchema, ReqState,
        },
        response::{GenericResponse, UserData, UserResponse, GenerateResponse},
    };
    use serde::{Serialize, Deserialize};

    async fn setup(state: AppState) -> TestServer {
        let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);
    

    let router = init_router(state, cors).await;
    TestServer::new(router).unwrap()
    }

    async fn impl_register() -> TestServer {
        let state = AppState::init();

        let server = setup(state).await;

        let reg = UserRegisterSchema {
            name: "test1 test".to_string(),
            email: "test1@test.tst".to_string(),
            password: "bob".to_string(),
        };

        let resp = server.post("/auth/register")
            .json(&reg).await;

        let reg = resp.json::<GenericResponse>();
        assert_eq!(reg.status, "success");
        server
    }

    #[tokio::test]
    async fn register() {
        let _srv = impl_register().await;  
    }

    async fn impl_login() -> (TestServer, UserData) {
        let server = impl_register().await; 

       let args = UserLoginSchema {
            email: "test1@test.tst".to_string(),
            password: "bob".to_string(),
        };

        let resp = server.post("/auth/login")
            .json(&args).await;

        let user = resp.json::<UserResponse>();
        assert_eq!(user.status, "success");
        (server, user.user)
    }

    #[tokio::test]
    async fn login() {
        let (_srv, _user) = impl_login().await;
    }

    async fn impl_generate() -> (TestServer, UserData) {
        let (server, user) = impl_login().await;

        let gen = GenerateOTPSchema {
            email: user.email.clone(),
            user_id: user.id.clone(),
        };

        let resp = server.post("/auth/otp/generate")
        .json(&gen).await;

        let qr = resp.json::<GenerateResponse>();
        println!("GEN {:?}", qr);
        (server, user)
    }

    #[tokio::test]
    async fn generate() {
        let (server, user) = impl_generate().await;
        println!("{:?}", user);
    }
}
