use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
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

// Role bitmask constants for axum-acl (u32)
pub const ROLE_GUEST: u32 = 0;       // Unauthenticated
pub const ROLE_USER: u32 = 1;        // Authenticated user
pub const ROLE_ADMIN: u32 = 2;       // Admin privileges

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

#[derive(Debug, Deserialize, Serialize, Clone, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub password: String,
    pub otp_enabled: bool,
    pub otp_verified: bool,
    pub otp_base32: Option<String>,
    pub otp_auth_url: Option<String>,
    pub role: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct DbSession {
    pub token: String,
    pub user_id: String,
    pub created_at: String,
    pub last_activity: String,
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

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub auth_limiter: RateLimiter,
    pub otp_limiter: RateLimiter,
}

impl AppState {
    pub async fn init(database_url: &str) -> Result<AppState, sqlx::Error> {
        let pool = SqlitePool::connect(database_url).await?;

        // Run migrations
        sqlx::query(include_str!("../migrations/001_initial.sql"))
            .execute(&pool)
            .await?;

        Ok(AppState {
            db: pool,
            // Auth endpoints: 10 requests per 60 seconds
            auth_limiter: RateLimiter::new(10, 60),
            // OTP endpoints: 5 requests per 60 seconds (stricter to prevent brute force)
            otp_limiter: RateLimiter::new(5, 60),
        })
    }

    pub async fn create_session(&self, user_id: &str) -> Result<String, sqlx::Error> {
        let token = generate_session_token();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO sessions (token, user_id, created_at, last_activity) VALUES (?, ?, ?, ?)"
        )
        .bind(&token)
        .bind(user_id)
        .bind(&now)
        .bind(&now)
        .execute(&self.db)
        .await?;

        Ok(token)
    }

    /// Returns (user_id, role) if session is valid
    pub async fn get_session(&self, token: &str) -> Result<Option<(String, i64)>, sqlx::Error> {
        let result = sqlx::query_as::<_, (String, i64)>(
            r#"
            SELECT s.user_id, u.role
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
              AND datetime(s.last_activity) > datetime('now', '-1 hour')
            "#
        )
        .bind(token)
        .fetch_optional(&self.db)
        .await?;

        if result.is_some() {
            // Update last_activity (sliding expiration)
            let now = Utc::now().to_rfc3339();
            sqlx::query("UPDATE sessions SET last_activity = ? WHERE token = ?")
                .bind(&now)
                .bind(token)
                .execute(&self.db)
                .await?;
        }

        Ok(result)
    }

    pub async fn destroy_session(&self, token: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(token)
            .execute(&self.db)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM sessions WHERE datetime(last_activity) < datetime('now', '-1 hour')"
        )
        .execute(&self.db)
        .await?;
        Ok(result.rows_affected())
    }
}

// User ID extracted from session by middleware
#[derive(Clone, Debug)]
pub struct UserId(pub String);

// User role extracted from session by middleware
#[derive(Clone, Debug)]
pub struct UserRole(pub u32);

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

// OTP operations require otp_token in body (session from header)
#[derive(Debug, Deserialize)]
pub struct OTPTokenSchema {
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
}
