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
        AppState, DisableOTPSchema, GenerateOTPSchema, User, UserLoginSchema, UserRegisterSchema,
        VerifyOTPSchema,
    },
    response::{GenericResponse, UserData, UserResponse},
};
use base32;
use chrono::prelude::*;
use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use axum::{
    extract::{State, Json}, 
    Router, routing::post,
    response::IntoResponse,
};
use serde_json::json;

const ISSUER: &str = "CRmep";

fn otp_routes(state: AppState) -> Router {
    let r = Router::new()
        .route("/generate", post(generate))
        .route("/verify", post(verify))
        .route("/validate", post(validate))
        .route("/disable", post(disable))
        .with_state(state);

    r
}

pub fn auth_routes(state: AppState) -> Router {
    let r = Router::new()
    .route("/register", post(register))
    .route("/login", post(login))
    .route("/profile", post(profile))
    .route("/logout", post(logout))
    .with_state(state.clone())
    .nest("/otp", otp_routes(state));


    r
}


#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    Json(reg): Json<UserRegisterSchema>

) -> impl IntoResponse {
    let mut usr = state.db.lock().unwrap();

    match usr
        .iter()
        .find(|&u| u.email == reg.email.to_lowercase()) {
        Some(u) => {
            println!("Found {:?}", u);
            let error_response = GenericResponse {
                status: "fail".to_string(),
                message: format!("User with email: {} already exists", u.email),
            };
            //return (StatusCode::NOT_FOUND, format!("User with email: {} already exists", error_response.message))
            return Json(json!(error_response))
        },
        None => ()
    };

    let uuid_id = Uuid::new_v4();
    let datetime = Utc::now();
    println!("{:?}", reg);
    let user = User {
        id: Some(uuid_id.to_string()),
        email: reg.email.to_owned().to_lowercase(),
        name: reg.name.to_owned(),
        password: reg.password.to_owned(),
        otp_enabled: false,
        otp_verified: false,
        otp_base32: None,
        otp_auth_url: None,
        createdAt: Some(datetime),
        updatedAt: Some(datetime),
        role: 0,
        sess: None,
    };

    println!("REG {:?} S=>{:?}",reg, user);
    usr.push(user);

    Json(json!({"data": 42}))


}

#[axum::debug_handler]
async fn login(
    State(state): State<AppState>,
    Json(reg): Json<UserLoginSchema>
) -> impl IntoResponse {
    let mut usr = state.db.lock().unwrap();

    let user = match usr
        .iter_mut()
        .find(|u| u.email == reg.email.to_lowercase()) {
            Some(u) => {
                // check password
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Invalid email or password"),
                };
                //return (StatusCode::NOT_FOUND, format!("User with email: {} already exists", error_response.message))
                return Json(json!(error_response))
            }
    };  

    user.otp_verified = false;

    let json_response = UserResponse {
        status: "success".to_string(),
        user: user_to_response(&user),
    };
    println!("LOGIN {:?}",&user);
    Json(json!(json_response))

}


#[axum::debug_handler]
async fn generate(
    State(state): State<AppState>,
    Json(gen): Json<GenerateOTPSchema>
) -> impl IntoResponse
{
    let mut usr = state.db.lock().unwrap();

    let user = match usr
        .iter_mut()
        .find(|u| u.email == gen.email.to_lowercase()) {
            Some(u) => {
                if u.otp_enabled {
                    println!("Already enabled");
                    let error_response = GenericResponse {
                        status: "fail".to_string(),
                        message: format!("F2A already enabled"),
                    };
                    return Json(json!(error_response))
                };
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("User Not Found"),
                };
                return Json(json!(error_response))
            }
    };

    let mut rng = rand::thread_rng();
    let data_byte: [u8; 21] = rng.gen();
    let base32_string = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &data_byte);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(base32_string).to_bytes().unwrap(),
        Some(ISSUER.to_string()),
        "crmep".to_string(),
    )
    .unwrap();

    let otp_base32 = totp.get_secret_base32();
    let email = gen.email.to_owned();
    let issuer = "CrMep";
    let otp_auth_url =
        format!("otpauth://totp/{issuer}:{email}?secret={otp_base32}&issuer={issuer}");

    // let otp_auth_url = format!("otpauth://totp/<issuer>:<account_name>?secret=<secret>&issuer=<issuer>");
    user.otp_base32 = Some(otp_base32.to_owned());
    user.otp_auth_url = Some(otp_auth_url.to_owned());
    user.otp_enabled = true;
    user.otp_verified = false;

    println!("GEN {:?}", &user);
    Json(json!({"base32":otp_base32.to_owned(), "otpauth_url": otp_auth_url.to_owned()} ))

}

#[axum::debug_handler]
async fn verify(
    State(state): State<AppState>,
    Json(verf): Json<VerifyOTPSchema>
) -> impl IntoResponse {
    let mut usr = state.db.lock().unwrap();

    let user = match usr
        .iter_mut()
        .find(|u| u.id == Some(verf.user_id.clone())) {
            Some(u) => {
                let datetime = Utc::now();
                u.updatedAt = Some(datetime);
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Invalid email or password"),
                };
                //return (StatusCode::NOT_FOUND, format!("User with email: {} already exists", error_response.message))
                return Json(json!(error_response))
            }
    };
    println!("VERIFY {:?}", &user);

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
        Some(ISSUER.to_string()),
        "crmep".to_string()
    )
    .unwrap();

    let is_valid = totp.check_current(&verf.token).unwrap();
    //println!("{:?} {:?}", otp_base32.clone(), totp, );
    if !is_valid {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "Token is invalid or user doesn't exist".to_string(),
        };

        return Json(json!(json_error))
    }

    user.otp_enabled = true;
    user.otp_verified = true;
    println!("VERVAL");
    Json(json!({"otp_verified": true, "user": user_to_response(user)}))

}

#[axum::debug_handler]
async fn validate(
    State(state): State<AppState>,
    Json(verf): Json<VerifyOTPSchema>
) -> impl IntoResponse {
    let usr = state.db.lock().unwrap();

    let user = match usr
        .iter()
        .find(|u| u.id == Some(verf.user_id.clone())) {
            Some(u) => {
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Invalid email or password"),
                };
                //return (StatusCode::NOT_FOUND, format!("User with email: {} already exists", error_response.message))
                return Json(json!(error_response))
            }
    };

    if !user.otp_enabled {
        let json_error = GenericResponse {
            status: "fail".to_string(),
            message: "2FA not enabled".to_string(),
        };

        return Json(json!(json_error))
    }

    let otp_base32 = user.otp_base32.to_owned().unwrap();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(otp_base32).to_bytes().unwrap(),
        Some(ISSUER.to_string()),
        "crmep".to_string(),
    )
    .unwrap();
    println!("{:?}",totp);
    let is_valid = totp.check_current(&verf.token).unwrap();
    println!("{:?}",is_valid);
    if !is_valid {
        return Json(json!(json!({"status": "fail", "message": "Token is invalid or user doesn't exist"})))
    }

    Json(json!({"otp_valid": true}))

}

#[axum::debug_handler]
async fn disable(
    State(state): State<AppState>,
    Json(dis): Json<DisableOTPSchema>
)  -> impl IntoResponse {
    let mut usr = state.db.lock().unwrap();

    let user = match usr
        .iter_mut()
        .find(|u| u.id == Some(dis.user_id.clone())) {
            Some(u) => {
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Invalid email or password"),
                };
                //return (StatusCode::NOT_FOUND, format!("User with email: {} already exists", error_response.message))
                return Json(json!(error_response))
            }
    };
    println!("DISABLED");
    user.otp_enabled = false;
    user.otp_verified = false;
    user.otp_auth_url = None;
    user.otp_base32 = None;
    
    Json(json!({"user": user_to_response(user), "otp_disabled": true}))
}

#[axum::debug_handler]
async fn profile(
    State(state): State<AppState>,
    Json(dis): Json<DisableOTPSchema>
)  -> impl IntoResponse {
    let usr = state.db.lock().unwrap();

    let user = match usr
        .iter()
        .find(|u| u.id == Some(dis.user_id.clone())) {
            Some(u) => {
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Invalid Id"),
                };
                return Json(json!(error_response))
            }
    };
    println!("PROFILE {:?}", user);
    Json(json!({"user": user_to_response(user)}))
}

#[axum::debug_handler]
async fn logout(
    State(state): State<AppState>,
    Json(dis): Json<DisableOTPSchema>
)  -> impl IntoResponse {
    let mut usr = state.db.lock().unwrap();

    let user = match usr
        .iter_mut()
        .find(|u| u.id == Some(dis.user_id.clone())) {
            Some(u) => {
                u.sess = None;
                u
            }
            None => {
                println!("Not Found");
                let error_response = GenericResponse {
                    status: "fail".to_string(),
                    message: format!("Invalid email or password"),
                };
                //return (StatusCode::NOT_FOUND, format!("User with email: {} already exists", error_response.message))
                return Json(json!(error_response))
            }
    };
    Json(json!({"otp_verified": true, "user": user_to_response(user)}))
}

fn user_to_response(user: &User) -> UserData {
    let ses = user.sess.clone().unwrap_or("".to_string());
    UserData {
        id: user.id.to_owned().unwrap(),
        name: user.name.to_owned(),
        email: user.email.to_owned(),
        otp_auth_url: user.otp_auth_url.to_owned(),
        otp_base32: user.otp_base32.to_owned(),
        otp_enabled: user.otp_enabled,
        otp_verified: user.otp_verified,
        createdAt: user.createdAt.unwrap(),
        updatedAt: user.updatedAt.unwrap(),
        sess: ses,
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
