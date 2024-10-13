use chrono::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct GenericResponse {
    pub status: String,
    pub message: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct UserData {
    pub id: String,
    pub email: String,
    pub name: String,

    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,

    pub createdAt: DateTime<Utc>,
    pub updatedAt: DateTime<Utc>,

    pub sess: String,
}

#[derive(Serialize, Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct UserResponse {
    pub status: String,
    pub user: UserData,
}

#[derive(Serialize, Debug)]
#[cfg_attr(test, derive(Deserialize))]
pub struct GenerateResponse {
    pub base32: String,
    otpauth_url: String,
}