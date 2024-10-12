
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: Option<String>,
    pub email: String,
    pub name: String,
    pub password: String,

    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,

    pub createdAt: Option<DateTime<Utc>>,
    pub updatedAt: Option<DateTime<Utc>>,

    pub sess: Option<String>,
    pub role: u64,
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: Arc<Mutex<Vec<User>>>,
}

impl AppState {
    pub fn init() -> AppState {
        AppState {
            db: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReqState {
    pub test: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct UserRegisterSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct UserLoginSchema {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct GenerateOTPSchema {
    pub email: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct VerifyOTPSchema {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct DisableOTPSchema {
    pub user_id: String,
}
