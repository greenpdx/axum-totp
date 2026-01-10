use crate::{
    models::{
        AppState, User, UserLoginSchema, UserRegisterSchema, OTPTokenSchema, UserId,
        is_valid_email, validate_name, validate_password, ROLE_USER,
    },
    response::{GenericResponse, UserData},
};
use axum::{
    extract::{Extension, State, Json},
    Router, routing::post,
    http::StatusCode,
};
use base32;
use bcrypt::{hash, verify as bcrypt_verify, DEFAULT_COST};
use chrono::prelude::*;
use serde_json::json;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

const ISSUER: &str = "CRmep";
// Generic auth error to prevent user enumeration
const AUTH_ERROR: &str = "Invalid credentials";
const SESSION_ERROR: &str = "Invalid or expired session";

type ApiResponse = (StatusCode, Json<serde_json::Value>);

fn error_response(message: &str) -> ApiResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(json!(GenericResponse {
            status: "fail".to_string(),
            message: message.to_string(),
        }))
    )
}

fn unauthorized_response() -> ApiResponse {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!(GenericResponse {
            status: "fail".to_string(),
            message: SESSION_ERROR.to_string(),
        }))
    )
}

fn success_response(data: serde_json::Value) -> ApiResponse {
    (StatusCode::OK, Json(data))
}

fn rate_limit_response() -> ApiResponse {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!(GenericResponse {
            status: "fail".to_string(),
            message: "Too many requests. Please try again later.".to_string(),
        }))
    )
}

fn internal_error() -> ApiResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!(GenericResponse {
            status: "fail".to_string(),
            message: "Internal server error".to_string(),
        }))
    )
}

fn create_totp(secret_base32: &str) -> Result<TOTP, String> {
    let secret_bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| format!("Invalid secret: {}", e))?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER.to_string()),
        "crmep".to_string(),
    )
    .map_err(|e| format!("Failed to create TOTP: {}", e))
}

fn otp_routes(state: AppState) -> Router {
    Router::new()
        .route("/generate", post(generate))
        .route("/verify", post(verify))
        .route("/validate", post(validate))
        .route("/disable", post(disable))
        .with_state(state)
}

pub fn auth_routes(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/profile", post(profile))
        .route("/logout", post(logout))
        .with_state(state.clone())
        .nest("/otp", otp_routes(state))
}


#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    Json(reg): Json<UserRegisterSchema>
) -> ApiResponse {
    // Input validation
    if !is_valid_email(&reg.email) {
        return error_response("Invalid email format");
    }
    if let Err(e) = validate_name(&reg.name) {
        return error_response(e);
    }
    if let Err(e) = validate_password(&reg.password) {
        return error_response(e);
    }

    // Rate limit by email
    if !state.auth_limiter.check(&reg.email.to_lowercase()) {
        return rate_limit_response();
    }

    // Check if email exists
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE email = ?"
    )
    .bind(&reg.email.to_lowercase())
    .fetch_one(&state.db)
    .await;

    match existing {
        Ok(count) if count > 0 => return error_response(AUTH_ERROR),
        Err(_) => return internal_error(),
        _ => {}
    }

    let uuid_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let password_hash = match hash(&reg.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return error_response("Registration failed"),
    };

    let result = sqlx::query(
        r#"INSERT INTO users
           (id, email, name, password, otp_enabled, otp_verified, role, created_at, updated_at)
           VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?)"#
    )
    .bind(&uuid_id)
    .bind(&reg.email.to_lowercase())
    .bind(&reg.name)
    .bind(&password_hash)
    .bind(ROLE_USER as i64)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => success_response(json!({"status": "success", "message": "User registered"})),
        Err(_) => internal_error(),
    }
}

#[axum::debug_handler]
async fn login(
    State(state): State<AppState>,
    Json(req): Json<UserLoginSchema>
) -> ApiResponse {
    // Input validation
    if !is_valid_email(&req.email) {
        return error_response(AUTH_ERROR);
    }

    // Rate limit by email
    if !state.auth_limiter.check(&req.email.to_lowercase()) {
        return rate_limit_response();
    }

    // Find user
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = ?"
    )
    .bind(&req.email.to_lowercase())
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(AUTH_ERROR),
        Err(_) => return internal_error(),
    };

    // Verify password
    let valid = bcrypt_verify(&req.password, &user.password).unwrap_or(false);
    if !valid {
        return error_response(AUTH_ERROR);
    }

    // Reset otp_verified on login
    let _ = sqlx::query("UPDATE users SET otp_verified = 0 WHERE id = ?")
        .bind(&user.id)
        .execute(&state.db)
        .await;

    // Create session token
    let session_token = match state.create_session(&user.id).await {
        Ok(token) => token,
        Err(_) => return error_response("Failed to create session"),
    };

    success_response(json!({
        "status": "success",
        "session_token": session_token,
        "otp_enabled": user.otp_enabled
    }))
}

#[axum::debug_handler]
async fn generate(
    State(state): State<AppState>,
    user_id: Option<Extension<UserId>>,
) -> ApiResponse {
    // Check authentication
    let user_id = match user_id {
        Some(Extension(id)) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by user_id
    if !state.otp_limiter.check(&user_id.0) {
        return rate_limit_response();
    }

    // Get user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id.0)
        .fetch_optional(&state.db)
        .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => return unauthorized_response(),
        Err(_) => return internal_error(),
    };

    if user.otp_enabled {
        return error_response("2FA already enabled");
    }

    // Generate random bytes before any async operations (to avoid Send issues)
    let data_byte: [u8; 21] = rand::random();
    let base32_string = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);

    let totp = match create_totp(&base32_string) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    let otp_base32 = totp.get_secret_base32();
    let email = user.email.clone();
    let issuer = "CrMep";
    let otp_auth_url = format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

    // Update user
    let result = sqlx::query(
        "UPDATE users SET otp_base32 = ?, otp_auth_url = ?, otp_enabled = 1, otp_verified = 0 WHERE id = ?"
    )
    .bind(&otp_base32)
    .bind(&otp_auth_url)
    .bind(&user_id.0)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => success_response(json!({"base32": otp_base32, "otpauth_url": otp_auth_url})),
        Err(_) => internal_error(),
    }
}

#[axum::debug_handler]
async fn verify(
    State(state): State<AppState>,
    user_id: Option<Extension<UserId>>,
    Json(req): Json<OTPTokenSchema>
) -> ApiResponse {
    // Check authentication
    let user_id = match user_id {
        Some(Extension(id)) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by user_id (strict)
    if !state.otp_limiter.check(&user_id.0) {
        return rate_limit_response();
    }

    // Get user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id.0)
        .fetch_optional(&state.db)
        .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => return unauthorized_response(),
        Err(_) => return internal_error(),
    };

    let otp_base32 = match &user.otp_base32 {
        Some(s) => s.clone(),
        None => return error_response("OTP not configured"),
    };

    let totp = match create_totp(&otp_base32) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    let is_valid = totp.check_current(&req.otp_token).unwrap_or(false);
    if !is_valid {
        return error_response("Invalid OTP token");
    }

    // Update user
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "UPDATE users SET otp_enabled = 1, otp_verified = 1, updated_at = ? WHERE id = ?"
    )
    .bind(&now)
    .bind(&user_id.0)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => success_response(json!({"otp_verified": true})),
        Err(_) => internal_error(),
    }
}

#[axum::debug_handler]
async fn validate(
    State(state): State<AppState>,
    user_id: Option<Extension<UserId>>,
    Json(req): Json<OTPTokenSchema>
) -> ApiResponse {
    // Check authentication
    let user_id = match user_id {
        Some(Extension(id)) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by user_id (strict)
    if !state.otp_limiter.check(&user_id.0) {
        return rate_limit_response();
    }

    // Get user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id.0)
        .fetch_optional(&state.db)
        .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => return unauthorized_response(),
        Err(_) => return internal_error(),
    };

    if !user.otp_enabled {
        return error_response("2FA not enabled");
    }

    let otp_base32 = match &user.otp_base32 {
        Some(s) => s.clone(),
        None => return error_response("OTP not configured"),
    };

    let totp = match create_totp(&otp_base32) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    let is_valid = totp.check_current(&req.otp_token).unwrap_or(false);
    if !is_valid {
        return error_response("Invalid OTP token");
    }

    success_response(json!({"otp_valid": true}))
}

#[axum::debug_handler]
async fn disable(
    State(state): State<AppState>,
    user_id: Option<Extension<UserId>>,
) -> ApiResponse {
    // Check authentication
    let user_id = match user_id {
        Some(Extension(id)) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by user_id
    if !state.otp_limiter.check(&user_id.0) {
        return rate_limit_response();
    }

    // Update user
    let result = sqlx::query(
        "UPDATE users SET otp_enabled = 0, otp_verified = 0, otp_base32 = NULL, otp_auth_url = NULL WHERE id = ?"
    )
    .bind(&user_id.0)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => success_response(json!({"otp_disabled": true})),
        Err(_) => internal_error(),
    }
}

#[axum::debug_handler]
async fn profile(
    State(state): State<AppState>,
    user_id: Option<Extension<UserId>>,
) -> ApiResponse {
    // Check authentication
    let user_id = match user_id {
        Some(Extension(id)) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by user_id
    if !state.auth_limiter.check(&user_id.0) {
        return rate_limit_response();
    }

    // Get user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id.0)
        .fetch_optional(&state.db)
        .await;

    match user {
        Ok(Some(u)) => success_response(json!({"user": user_to_response(&u)})),
        Ok(None) => unauthorized_response(),
        Err(_) => internal_error(),
    }
}

#[axum::debug_handler]
async fn logout(
    State(state): State<AppState>,
    user_id: Option<Extension<UserId>>,
    headers: axum::http::HeaderMap,
) -> ApiResponse {
    // Check authentication
    let user_id = match user_id {
        Some(Extension(id)) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by user_id
    if !state.auth_limiter.check(&user_id.0) {
        return rate_limit_response();
    }

    // Get token from header and destroy session
    if let Some(token) = headers.get("X-Session-Token").and_then(|v| v.to_str().ok()) {
        let _ = state.destroy_session(token).await;
    }

    success_response(json!({"logged_out": true}))
}

fn user_to_response(user: &User) -> UserData {
    UserData {
        id: user.id.clone(),
        name: user.name.clone(),
        email: user.email.clone(),
        otp_enabled: user.otp_enabled,
        otp_verified: user.otp_verified,
        created_at: user.created_at.clone(),
        updated_at: user.updated_at.clone(),
    }
}
