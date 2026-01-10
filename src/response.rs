use serde::Serialize;

#[derive(Serialize)]
pub struct GenericResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct UserData {
    pub id: String,
    pub email: String,
    pub name: String,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Debug)]
pub struct UserResponse {
    pub status: String,
    pub user: UserData,
}
