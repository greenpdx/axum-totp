use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware,
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use axum_totp::{
    acl::auth_middleware,
    models::AppState,
    services::auth_routes,
};

async fn create_test_app() -> (Router, AppState) {
    // Use in-memory SQLite for tests
    let state = AppState::init("sqlite::memory:").await.unwrap();
    let auth = auth_routes(state.clone());
    let app = Router::new()
        .nest("/auth", auth)
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));
    (app, state)
}

async fn send_json_request(app: Router, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

    (status, body)
}

async fn send_json_request_with_session(
    app: Router,
    method: &str,
    uri: &str,
    body: Value,
    session_token: &str,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("X-Session-Token", session_token)
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

    (status, body)
}

fn create_app_with_state(state: AppState) -> Router {
    let auth = auth_routes(state.clone());
    Router::new()
        .nest("/auth", auth)
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
}

mod register {
    use super::*;

    #[tokio::test]
    async fn successful_registration() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "Test User",
                "email": "test@example.com",
                "password": "password123"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "success");
    }

    #[tokio::test]
    async fn invalid_email_format() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "Test User",
                "email": "invalid-email",
                "password": "password123"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn password_too_short() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "Test User",
                "email": "test@example.com",
                "password": "short"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn empty_name() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "",
                "email": "test@example.com",
                "password": "password123"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "fail");
    }
}

mod login {
    use super::*;

    #[tokio::test]
    async fn successful_login() {
        let (_, state) = create_test_app().await;

        // Register first
        let app = create_app_with_state(state.clone());
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "Test User",
                "email": "login@example.com",
                "password": "password123"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Login with same state
        let app = create_app_with_state(state);
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/login",
            json!({
                "email": "login@example.com",
                "password": "password123"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "success");
        assert!(body["session_token"].is_string());
    }

    #[tokio::test]
    async fn invalid_credentials() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/login",
            json!({
                "email": "nonexistent@example.com",
                "password": "wrongpassword"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn invalid_email_format() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/login",
            json!({
                "email": "not-an-email",
                "password": "password123"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "fail");
    }
}

mod profile {
    use super::*;

    #[tokio::test]
    async fn no_session_header() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/profile",
            json!({}),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn invalid_session() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request_with_session(
            app,
            "POST",
            "/auth/profile",
            json!({}),
            "invalid_token",
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn valid_session_returns_profile() {
        let (_, state) = create_test_app().await;

        // Register
        let app = create_app_with_state(state.clone());
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "Profile User",
                "email": "profile@example.com",
                "password": "password123"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Login
        let app = create_app_with_state(state.clone());
        let (status, login_body) = send_json_request(
            app,
            "POST",
            "/auth/login",
            json!({
                "email": "profile@example.com",
                "password": "password123"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let session_token = login_body["session_token"].as_str().unwrap();

        // Get profile with session header
        let app = create_app_with_state(state);
        let (status, body) = send_json_request_with_session(
            app,
            "POST",
            "/auth/profile",
            json!({}),
            session_token,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["email"], "profile@example.com");
        assert_eq!(body["user"]["name"], "Profile User");
    }
}

mod logout {
    use super::*;

    #[tokio::test]
    async fn successful_logout() {
        let (_, state) = create_test_app().await;

        // Register
        let app = create_app_with_state(state.clone());
        let _ = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "Logout User",
                "email": "logout@example.com",
                "password": "password123"
            }),
        )
        .await;

        // Login
        let app = create_app_with_state(state.clone());
        let (_, login_body) = send_json_request(
            app,
            "POST",
            "/auth/login",
            json!({
                "email": "logout@example.com",
                "password": "password123"
            }),
        )
        .await;
        let session_token = login_body["session_token"].as_str().unwrap();

        // Logout with session header
        let app = create_app_with_state(state.clone());
        let (status, body) = send_json_request_with_session(
            app,
            "POST",
            "/auth/logout",
            json!({}),
            session_token,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["logged_out"], true);

        // Verify session is invalid after logout
        let app = create_app_with_state(state);
        let (status, _) = send_json_request_with_session(
            app,
            "POST",
            "/auth/profile",
            json!({}),
            session_token,
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_invalid_session() {
        let (app, _) = create_test_app().await;
        let (status, _) = send_json_request_with_session(
            app,
            "POST",
            "/auth/logout",
            json!({}),
            "invalid_token",
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

mod otp {
    use super::*;

    async fn setup_authenticated_user(state: &AppState) -> String {
        // Register
        let app = create_app_with_state(state.clone());
        let _ = send_json_request(
            app,
            "POST",
            "/auth/register",
            json!({
                "name": "OTP User",
                "email": "otp@example.com",
                "password": "password123"
            }),
        )
        .await;

        // Login
        let app = create_app_with_state(state.clone());
        let (_, login_body) = send_json_request(
            app,
            "POST",
            "/auth/login",
            json!({
                "email": "otp@example.com",
                "password": "password123"
            }),
        )
        .await;

        login_body["session_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn generate_otp_requires_auth() {
        let (app, _) = create_test_app().await;
        let (status, body) = send_json_request_with_session(
            app,
            "POST",
            "/auth/otp/generate",
            json!({}),
            "invalid_token",
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn generate_otp_success() {
        let (_, state) = create_test_app().await;
        let session_token = setup_authenticated_user(&state).await;

        let app = create_app_with_state(state);
        let (status, body) = send_json_request_with_session(
            app,
            "POST",
            "/auth/otp/generate",
            json!({}),
            &session_token,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body["base32"].is_string());
        assert!(body["otpauth_url"].is_string());
    }

    #[tokio::test]
    async fn verify_otp_requires_auth() {
        let (app, _) = create_test_app().await;
        let (status, _) = send_json_request_with_session(
            app,
            "POST",
            "/auth/otp/verify",
            json!({
                "otp_token": "123456"
            }),
            "invalid_token",
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_otp_requires_auth() {
        let (app, _) = create_test_app().await;
        let (status, _) = send_json_request_with_session(
            app,
            "POST",
            "/auth/otp/validate",
            json!({
                "otp_token": "123456"
            }),
            "invalid_token",
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn disable_otp_requires_auth() {
        let (app, _) = create_test_app().await;
        let (status, _) = send_json_request_with_session(
            app,
            "POST",
            "/auth/otp/disable",
            json!({}),
            "invalid_token",
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
