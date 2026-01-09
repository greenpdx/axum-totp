use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use axum_topo::{
    models::AppState,
    services::auth_routes,
};

fn create_test_app() -> Router {
    let state = AppState::init();
    Router::new().nest("/auth", auth_routes(state))
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

mod register {
    use super::*;

    #[tokio::test]
    async fn successful_registration() {
        let app = create_test_app();
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
        let app = create_test_app();
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
        let app = create_test_app();
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
        let app = create_test_app();
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
        let state = AppState::init();
        let app = Router::new().nest("/auth", auth_routes(state.clone()));

        // Register first
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
        let app = Router::new().nest("/auth", auth_routes(state));
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
        let app = create_test_app();
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
        let app = create_test_app();
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
    async fn invalid_session() {
        let app = create_test_app();
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/profile",
            json!({
                "session_token": "invalid_token"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn valid_session_returns_profile() {
        let state = AppState::init();

        // Register
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
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
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
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

        // Get profile
        let app = Router::new().nest("/auth", auth_routes(state));
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/profile",
            json!({
                "session_token": session_token
            }),
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
        let state = AppState::init();

        // Register
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
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
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
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

        // Logout
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/logout",
            json!({
                "session_token": session_token
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["logged_out"], true);

        // Verify session is invalid after logout
        let app = Router::new().nest("/auth", auth_routes(state));
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/profile",
            json!({
                "session_token": session_token
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_invalid_session() {
        let app = create_test_app();
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/logout",
            json!({
                "session_token": "invalid_token"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

mod otp {
    use super::*;

    async fn setup_authenticated_user(state: &AppState) -> String {
        // Register
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
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
        let app = Router::new().nest("/auth", auth_routes(state.clone()));
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
        let app = create_test_app();
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/otp/generate",
            json!({
                "session_token": "invalid_token"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["status"], "fail");
    }

    #[tokio::test]
    async fn generate_otp_success() {
        let state = AppState::init();
        let session_token = setup_authenticated_user(&state).await;

        let app = Router::new().nest("/auth", auth_routes(state));
        let (status, body) = send_json_request(
            app,
            "POST",
            "/auth/otp/generate",
            json!({
                "session_token": session_token
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(body["base32"].is_string());
        assert!(body["otpauth_url"].is_string());
    }

    #[tokio::test]
    async fn verify_otp_requires_auth() {
        let app = create_test_app();
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/otp/verify",
            json!({
                "session_token": "invalid_token",
                "otp_token": "123456"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_otp_requires_auth() {
        let app = create_test_app();
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/otp/validate",
            json!({
                "session_token": "invalid_token",
                "otp_token": "123456"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn disable_otp_requires_auth() {
        let app = create_test_app();
        let (status, _) = send_json_request(
            app,
            "POST",
            "/auth/otp/disable",
            json!({
                "session_token": "invalid_token"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
