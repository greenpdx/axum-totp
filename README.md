# axum-totp

A Rust web server implementing user authentication with TOTP (Time-based One-Time Password) two-factor authentication, built with Axum and SQLite.

## Features

- User registration and login with bcrypt password hashing
- Session-based authentication with automatic expiration
- TOTP 2FA (compatible with Google Authenticator, Authy, etc.)
- Rate limiting to prevent brute force attacks
- Input validation for emails, passwords, and names
- SQLite database for persistent storage
- Header-based session authentication

## Requirements

- Rust 1.85+ (2024 edition)
- Cargo

## Quick Start

```bash
# Clone and build
git clone https://github.com/greenpdx/axum-totp
cd axum-totp
cargo build --release

# Run the server
cargo run --release
```

The server starts at `http://0.0.0.0:8000` and creates a `data.db` SQLite file for storage.

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register a new user | No |
| POST | `/auth/login` | Login and get session token | No |
| POST | `/auth/profile` | Get user profile | Yes |
| POST | `/auth/logout` | Logout and invalidate session | Yes |

### Two-Factor Authentication (OTP)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/otp/generate` | Generate OTP secret and QR URL | Yes |
| POST | `/auth/otp/verify` | Verify and enable 2FA | Yes |
| POST | `/auth/otp/validate` | Validate OTP token | Yes |
| POST | `/auth/otp/disable` | Disable 2FA | Yes |

## Authentication

For authenticated endpoints, pass the session token in the `X-Session-Token` header:

```bash
curl -X POST http://localhost:8000/auth/profile \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token"
```

## API Usage

### Register

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "password": "securepassword"}'
```

### Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@example.com", "password": "securepassword"}'
```

Response:
```json
{
  "status": "success",
  "session_token": "abc123...",
  "otp_enabled": false
}
```

### Get Profile

```bash
curl -X POST http://localhost:8000/auth/profile \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token"
```

### Generate OTP Secret

```bash
curl -X POST http://localhost:8000/auth/otp/generate \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token"
```

Response:
```json
{
  "base32": "JBSWY3DPEHPK3PXP...",
  "otpauth_url": "otpauth://totp/CrMep:john@example.com?secret=..."
}
```

### Verify OTP (Enable 2FA)

```bash
curl -X POST http://localhost:8000/auth/otp/verify \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token" \
  -d '{"otp_token": "123456"}'
```

### Validate OTP

```bash
curl -X POST http://localhost:8000/auth/otp/validate \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token" \
  -d '{"otp_token": "123456"}'
```

### Disable OTP

```bash
curl -X POST http://localhost:8000/auth/otp/disable \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token"
```

### Logout

```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: your_session_token"
```

## Security Features

- **Password Hashing**: bcrypt with default cost factor
- **Session Management**: Cryptographically random tokens, 1-hour expiration with sliding window
- **Rate Limiting**:
  - Auth endpoints: 10 requests/minute per email
  - OTP endpoints: 5 requests/minute per session (stricter to prevent brute force)
- **Input Validation**: Email format, password length (8-128 chars), name length
- **Database**: SQLite with foreign key constraints

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Project Structure

```
src/
├── main.rs      # Server setup and router configuration
├── lib.rs       # Library exports
├── acl.rs       # Authentication middleware
├── models.rs    # Data models, validation, session management
├── services.rs  # API route handlers
└── response.rs  # Response types
migrations/
└── 001_initial.sql  # Database schema
tests/
└── integration_tests.rs  # API integration tests
```

## Dependencies

- **axum** 0.8 - Web framework
- **sqlx** 0.8 - Async SQLite database
- **tokio** - Async runtime
- **bcrypt** - Password hashing
- **totp-rs** - TOTP implementation
- **serde** - Serialization
- **tower-http** - HTTP middleware (CORS, tracing)

## License

LGPL-2.1
