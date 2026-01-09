/*
/healthchecker
/auth/register
/auth/login
/auth/otp/generate
/auth/otp/verify
/auth/otp/validate
/auth/otp/disable

*/

use crate::{
    models::{
        AppState, User, UserLoginSchema, UserRegisterSchema,
        SessionSchema, OTPTokenSchema,
        is_valid_email, validate_name, validate_password,
    },
    response::{GenericResponse, UserData},
};
use base32;
use bcrypt::{hash, verify as bcrypt_verify, DEFAULT_COST};
use chrono::prelude::*;
use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use axum::{
    extract::{State, Json},
    Router, routing::post,
};
use serde_json::json;
use axum::http::StatusCode;

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

    let mut usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    // Don't reveal if email exists - use generic message
    if usr.iter().any(|u| u.email == reg.email.to_lowercase()) {
        return error_response(AUTH_ERROR);
    }

    let uuid_id = Uuid::new_v4();
    let datetime = Utc::now();

    let password_hash = match hash(&reg.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return error_response("Registration failed"),
    };

    let user = User {
        id: Some(uuid_id.to_string()),
        email: reg.email.to_lowercase(),
        name: reg.name.clone(),
        password: password_hash,
        otp_enabled: false,
        otp_verified: false,
        otp_base32: None,
        otp_auth_url: None,
        createdAt: Some(datetime),
        updatedAt: Some(datetime),
        role: 0,
        sess: None,
    };

    usr.push(user);
    success_response(json!({"status": "success", "message": "User registered"}))
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

    let mut usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    let user = match usr
        .iter_mut()
        .find(|u| u.email == req.email.to_lowercase()) {
            Some(u) => {
                // Use constant-time comparison via bcrypt
                let valid = bcrypt_verify(&req.password, &u.password).unwrap_or(false);
                if !valid {
                    return error_response(AUTH_ERROR);
                }
                u
            }
            None => {
                // Same error message to prevent enumeration
                return error_response(AUTH_ERROR);
            }
    };

    user.otp_verified = false;

    // Create session token
    let user_id = user.id.clone().unwrap_or_default();
    drop(usr); // Release lock before creating session

    let session_token = match state.create_session(&user_id) {
        Some(token) => token,
        None => return error_response("Failed to create session"),
    };

    success_response(json!({
        "status": "success",
        "session_token": session_token,
        "otp_enabled": state.db.lock().ok()
            .and_then(|db| db.iter().find(|u| u.id == Some(user_id.clone())).map(|u| u.otp_enabled))
            .unwrap_or(false)
    }))
}


#[axum::debug_handler]
async fn generate(
    State(state): State<AppState>,
    Json(req): Json<SessionSchema>
) -> ApiResponse {
    // Validate session and get user_id
    let user_id = match state.get_user_id_from_session(&req.session_token) {
        Some(id) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by session token
    if !state.otp_limiter.check(&req.session_token) {
        return rate_limit_response();
    }

    let mut usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    let user = match usr.iter_mut().find(|u| u.id == Some(user_id.clone())) {
        Some(u) => {
            if u.otp_enabled {
                return error_response("2FA already enabled");
            }
            u
        }
        None => return unauthorized_response(),
    };

    let mut rng = rand::rng();
    let data_byte: [u8; 21] = rng.random();
    let base32_string = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);

    let totp = match create_totp(&base32_string) {
        Ok(t) => t,
        Err(e) => return error_response(&e),
    };

    let otp_base32 = totp.get_secret_base32();
    let email = user.email.clone();
    let issuer = "CrMep";
    let otp_auth_url = format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

    user.otp_base32 = Some(otp_base32.clone());
    user.otp_auth_url = Some(otp_auth_url.clone());
    user.otp_enabled = true;
    user.otp_verified = false;

    success_response(json!({"base32": otp_base32, "otpauth_url": otp_auth_url}))
}

#[axum::debug_handler]
async fn verify(
    State(state): State<AppState>,
    Json(req): Json<OTPTokenSchema>
) -> ApiResponse {
    // Validate session
    let user_id = match state.get_user_id_from_session(&req.session_token) {
        Some(id) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by session token (strict)
    if !state.otp_limiter.check(&req.session_token) {
        return rate_limit_response();
    }

    let mut usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    let user = match usr.iter_mut().find(|u| u.id == Some(user_id.clone())) {
        Some(u) => {
            u.updatedAt = Some(Utc::now());
            u
        }
        None => return unauthorized_response(),
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

    user.otp_enabled = true;
    user.otp_verified = true;
    success_response(json!({"otp_verified": true}))
}

#[axum::debug_handler]
async fn validate(
    State(state): State<AppState>,
    Json(req): Json<OTPTokenSchema>
) -> ApiResponse {
    // Validate session
    let user_id = match state.get_user_id_from_session(&req.session_token) {
        Some(id) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by session token (strict)
    if !state.otp_limiter.check(&req.session_token) {
        return rate_limit_response();
    }

    let usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    let user = match usr.iter().find(|u| u.id == Some(user_id.clone())) {
        Some(u) => u,
        None => return unauthorized_response(),
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
    Json(req): Json<SessionSchema>
) -> ApiResponse {
    // Validate session
    let user_id = match state.get_user_id_from_session(&req.session_token) {
        Some(id) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by session token
    if !state.otp_limiter.check(&req.session_token) {
        return rate_limit_response();
    }

    let mut usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    let user = match usr.iter_mut().find(|u| u.id == Some(user_id.clone())) {
        Some(u) => u,
        None => return unauthorized_response(),
    };

    user.otp_enabled = false;
    user.otp_verified = false;
    user.otp_auth_url = None;
    user.otp_base32 = None;

    success_response(json!({"otp_disabled": true}))
}

#[axum::debug_handler]
async fn profile(
    State(state): State<AppState>,
    Json(req): Json<SessionSchema>
) -> ApiResponse {
    // Validate session
    let user_id = match state.get_user_id_from_session(&req.session_token) {
        Some(id) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by session token
    if !state.auth_limiter.check(&req.session_token) {
        return rate_limit_response();
    }

    let usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    let user = match usr.iter().find(|u| u.id == Some(user_id.clone())) {
        Some(u) => u,
        None => return unauthorized_response(),
    };

    success_response(json!({"user": user_to_response(user)}))
}

#[axum::debug_handler]
async fn logout(
    State(state): State<AppState>,
    Json(req): Json<SessionSchema>
) -> ApiResponse {
    // Validate and destroy session
    let user_id = match state.get_user_id_from_session(&req.session_token) {
        Some(id) => id,
        None => return unauthorized_response(),
    };

    // Rate limit by session token
    if !state.auth_limiter.check(&req.session_token) {
        return rate_limit_response();
    }

    // Destroy the session
    state.destroy_session(&req.session_token);

    let mut usr = match state.db.lock() {
        Ok(guard) => guard,
        Err(_) => return error_response("Internal server error"),
    };

    // Clear user session field if exists
    if let Some(user) = usr.iter_mut().find(|u| u.id == Some(user_id.clone())) {
        user.sess = None;
    }

    success_response(json!({"logged_out": true}))
}

fn user_to_response(user: &User) -> UserData {
    UserData {
        id: user.id.clone().unwrap_or_default(),
        name: user.name.clone(),
        email: user.email.clone(),
        // Don't expose OTP secrets in response
        otp_auth_url: None,
        otp_base32: None,
        otp_enabled: user.otp_enabled,
        otp_verified: user.otp_verified,
        createdAt: user.createdAt.unwrap_or_else(Utc::now),
        updatedAt: user.updatedAt.unwrap_or_else(Utc::now),
        sess: String::new(), // Don't expose session
    }
}

/*
pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        .service(health_checker_handler)
        .service(register_user_handler)
        .service(login_user_handler)
        .service(generate_otp_handler)
        .service(verify_otp_handler)
        .service(validate_otp_handler)
        .service(disable_otp_handler);

    conf.service(scope);
}*/
