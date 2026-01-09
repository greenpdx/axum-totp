
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
    let mut rng = rand::rng();
    let bytes: [u8; SESSION_TOKEN_LENGTH] = rng.random();
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

#[cfg(test)]
mod tests {
    use super::*;

    mod email_validation {
        use super::*;

        #[test]
        fn valid_email() {
            assert!(is_valid_email("test@example.com"));
            assert!(is_valid_email("user.name@domain.co.uk"));
            assert!(is_valid_email("a@b.co"));
        }

        #[test]
        fn invalid_email_no_at() {
            assert!(!is_valid_email("testexample.com"));
        }

        #[test]
        fn invalid_email_no_domain() {
            assert!(!is_valid_email("test@"));
        }

        #[test]
        fn invalid_email_no_local() {
            assert!(!is_valid_email("@example.com"));
        }

        #[test]
        fn invalid_email_no_dot_in_domain() {
            assert!(!is_valid_email("test@example"));
        }

        #[test]
        fn invalid_email_empty() {
            assert!(!is_valid_email(""));
        }

        #[test]
        fn invalid_email_too_long() {
            let long_email = format!("{}@example.com", "a".repeat(300));
            assert!(!is_valid_email(&long_email));
        }

        #[test]
        fn invalid_email_multiple_at() {
            assert!(!is_valid_email("test@@example.com"));
            assert!(!is_valid_email("test@exam@ple.com"));
        }
    }

    mod name_validation {
        use super::*;

        #[test]
        fn valid_name() {
            assert!(validate_name("John Doe").is_ok());
            assert!(validate_name("A").is_ok());
        }

        #[test]
        fn invalid_name_empty() {
            assert!(validate_name("").is_err());
        }

        #[test]
        fn invalid_name_too_long() {
            let long_name = "a".repeat(MAX_NAME_LENGTH + 1);
            assert!(validate_name(&long_name).is_err());
        }
    }

    mod password_validation {
        use super::*;

        #[test]
        fn valid_password() {
            assert!(validate_password("password123").is_ok());
            assert!(validate_password("12345678").is_ok());
        }

        #[test]
        fn invalid_password_too_short() {
            assert!(validate_password("1234567").is_err());
            assert!(validate_password("").is_err());
        }

        #[test]
        fn invalid_password_too_long() {
            let long_password = "a".repeat(MAX_PASSWORD_LENGTH + 1);
            assert!(validate_password(&long_password).is_err());
        }
    }

    mod session_token {
        use super::*;

        #[test]
        fn generates_correct_length() {
            let token = generate_session_token();
            // Each byte becomes 2 hex chars
            assert_eq!(token.len(), SESSION_TOKEN_LENGTH * 2);
        }

        #[test]
        fn generates_unique_tokens() {
            let token1 = generate_session_token();
            let token2 = generate_session_token();
            assert_ne!(token1, token2);
        }

        #[test]
        fn generates_hex_string() {
            let token = generate_session_token();
            assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    mod rate_limiter {
        use super::*;
        use std::thread;
        use std::time::Duration;

        #[test]
        fn allows_requests_within_limit() {
            let limiter = RateLimiter::new(5, 60);
            for _ in 0..5 {
                assert!(limiter.check("test_key"));
            }
        }

        #[test]
        fn blocks_requests_over_limit() {
            let limiter = RateLimiter::new(3, 60);
            assert!(limiter.check("test_key"));
            assert!(limiter.check("test_key"));
            assert!(limiter.check("test_key"));
            assert!(!limiter.check("test_key"));
        }

        #[test]
        fn different_keys_have_separate_limits() {
            let limiter = RateLimiter::new(2, 60);
            assert!(limiter.check("key1"));
            assert!(limiter.check("key1"));
            assert!(!limiter.check("key1"));

            assert!(limiter.check("key2"));
            assert!(limiter.check("key2"));
        }

        #[test]
        fn resets_after_window_expires() {
            let limiter = RateLimiter::new(2, 1); // 1 second window
            assert!(limiter.check("test_key"));
            assert!(limiter.check("test_key"));
            assert!(!limiter.check("test_key"));

            thread::sleep(Duration::from_secs(2));
            assert!(limiter.check("test_key"));
        }
    }

    mod session_management {
        use super::*;

        #[test]
        fn session_creation() {
            let session = Session::new("user123".to_string());
            assert_eq!(session.user_id, "user123");
            assert!(!session.is_expired());
        }

        #[test]
        fn session_touch_updates_activity() {
            let mut session = Session::new("user123".to_string());
            let initial_activity = session.last_activity;
            std::thread::sleep(std::time::Duration::from_millis(10));
            session.touch();
            assert!(session.last_activity > initial_activity);
        }
    }

    mod app_state {
        use super::*;

        #[test]
        fn creates_and_validates_session() {
            let state = AppState::init();
            let token = state.create_session("user123").unwrap();

            let user_id = state.get_user_id_from_session(&token);
            assert_eq!(user_id, Some("user123".to_string()));
        }

        #[test]
        fn invalid_session_returns_none() {
            let state = AppState::init();
            let user_id = state.get_user_id_from_session("invalid_token");
            assert!(user_id.is_none());
        }

        #[test]
        fn destroys_session() {
            let state = AppState::init();
            let token = state.create_session("user123").unwrap();

            assert!(state.destroy_session(&token));
            assert!(state.get_user_id_from_session(&token).is_none());
        }

        #[test]
        fn destroy_nonexistent_session_returns_false() {
            let state = AppState::init();
            assert!(!state.destroy_session("nonexistent"));
        }
    }
}
