use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    body::Body,
    Json,
};
use serde_json::json;

use crate::models::{AppState, UserId, UserRole, ROLE_GUEST};

/// Middleware that extracts user ID and role from X-Session-Token header
/// and injects them as extensions for use by handlers
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Try to extract session token from X-Session-Token header
    if let Some(token) = request
        .headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(Some((user_id, role))) = state.get_session(token).await {
            // Store user ID and role in request extensions
            request.extensions_mut().insert(UserId(user_id));
            request.extensions_mut().insert(UserRole(role as u32));
        }
    }

    // If no valid session, set guest role (but no UserId)
    if request.extensions().get::<UserRole>().is_none() {
        request.extensions_mut().insert(UserRole(ROLE_GUEST));
    }

    next.run(request).await
}

/// Helper function for handlers to check authentication
/// Returns 401 Unauthorized response
pub fn unauthorized_json() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "status": "fail",
            "message": "Invalid or expired session"
        })),
    )
        .into_response()
}
