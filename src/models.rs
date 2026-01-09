
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use rand::Rng;

// Validation constants
pub const MAX_EMAIL_LENGTH: usize = 254;
pub const MAX_NAME_LENGTH: usize = 100;
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const SESSION_TOKEN_LENGTH: usize = 32;
pub const SESSION_TIMEOUT_SECS: u64 = 3600; // 1 hour

// Simple email validation (checks for @ and .)
pub fn is_valid_email(email: &str) -> bool {
    if email.len() > MAX_EMAIL_LENGTH || email.is_empty() {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("Name cannot be empty");
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err("Name too long");
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err("Password must be at least 8 characters");
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err("Password too long");
    }
    Ok(())
}

pub fn generate_session_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; SESSION_TOKEN_LENGTH] = rng.gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

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
pub struct RateLimitEntry {
    pub count: u32,
    pub window_start: Instant,
}

#[derive(Clone)]
pub struct RateLimiter {
    pub entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
    pub max_requests: u32,
    pub window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_secs,
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let mut entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };

        let now = Instant::now();
        let entry = entries.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start).as_secs() >= self.window_secs {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.max_requests {
            return false;
        }

        entry.count += 1;
        true
    }
}

// Session with expiration
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: String,
    pub created_at: Instant,
    pub last_activity: Instant,
}

impl Session {
    pub fn new(user_id: String) -> Self {
        let now = Instant::now();
        Self {
            user_id,
            created_at: now,
            last_activity: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed().as_secs() >= SESSION_TIMEOUT_SECS
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

// Maps session token -> Session
pub type SessionStore = Arc<Mutex<HashMap<String, Session>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Vec<User>>>,
    pub sessions: SessionStore,
    pub auth_limiter: RateLimiter,
    pub otp_limiter: RateLimiter,
}

impl AppState {
    pub fn init() -> AppState {
        AppState {
            db: Arc::new(Mutex::new(Vec::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            // Auth endpoints: 10 requests per 60 seconds
            auth_limiter: RateLimiter::new(10, 60),
            // OTP endpoints: 5 requests per 60 seconds (stricter to prevent brute force)
            otp_limiter: RateLimiter::new(5, 60),
        }
    }

    pub fn create_session(&self, user_id: &str) -> Option<String> {
        let token = generate_session_token();
        let mut sessions = self.sessions.lock().ok()?;
        sessions.insert(token.clone(), Session::new(user_id.to_string()));
        Some(token)
    }

    pub fn get_user_id_from_session(&self, token: &str) -> Option<String> {
        let mut sessions = self.sessions.lock().ok()?;

        // Check if session exists and is not expired
        if let Some(session) = sessions.get_mut(token) {
            if session.is_expired() {
                sessions.remove(token);
                return None;
            }
            // Update last activity (sliding expiration)
            session.touch();
            return Some(session.user_id.clone());
        }
        None
    }

    pub fn destroy_session(&self, token: &str) -> bool {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(token).is_some()
        } else {
            false
        }
    }

    // Cleanup expired sessions (call periodically)
    pub fn cleanup_expired_sessions(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, session| !session.is_expired());
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UserRegisterSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UserLoginSchema {
    pub email: String,
    pub password: String,
}

// Uses session token for authentication
#[derive(Debug, Deserialize)]
pub struct SessionSchema {
    pub session_token: String,
}

// OTP operations require session + token
#[derive(Debug, Deserialize)]
pub struct OTPTokenSchema {
    pub session_token: String,
    pub otp_token: String,
}
