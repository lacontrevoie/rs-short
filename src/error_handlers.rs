use actix_web::{HttpResponse, HttpRequest, Result};
use actix_session::Session;
use actix_web::dev::HttpResponseBuilder;
use actix_web::{error, http::header, http::StatusCode};
use std::fmt;

use crate::templates::{gentpl_home, TplNotification, get_lang};
use crate::spam::cookie_captcha_set;
use crate::init::ValidLanguages;


// 404 handler
pub async fn error_404(req: HttpRequest, s: Session) -> Result<HttpResponse> {
    let l = get_lang(&req);
    let captcha = cookie_captcha_set(&s);

    let tpl = TplNotification::new("home", "error_404", false, &l);
    return HttpResponse::NotFound().content_type("text/html").body(
        gentpl_home(&l, captcha.as_deref(), None, Some(&tpl))
    ).await;
}


pub fn crash(error_msg: &'static str, lang: ValidLanguages, captcha: Option<Vec<u8>>) -> ShortCircuit {
    ShortCircuit { error_msg, lang, captcha }
}

#[derive(Debug)]
pub struct ShortCircuit {
    pub error_msg: &'static str,
    pub lang: ValidLanguages,
    pub captcha: Option<Vec<u8>>,
}

// gonna avoid using failure crate
// by implementing display
impl fmt::Display for ShortCircuit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.error_msg)
    }
}

impl error::ResponseError for ShortCircuit {
    fn error_response(&self) -> HttpResponse {
        eprintln!("Error reached: {}", self.error_msg);
        
        let tpl = TplNotification::new("home", self.error_msg, false, &self.lang);

        HttpResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(gentpl_home(&self.lang, self.captcha.as_deref(), None, Some(&tpl)))
    }
    fn status_code(&self) -> StatusCode {
        match self.error_msg {
            "error_bad_server_admin_key" => StatusCode::UNAUTHORIZED,
            "error_invalid_key" => StatusCode::UNAUTHORIZED,
            "error_db_fail" => StatusCode::INTERNAL_SERVER_ERROR,
            "error_link_delete_db_fail" => StatusCode::INTERNAL_SERVER_ERROR,
            "error_link_not_found" => StatusCode::NOT_FOUND,
            "error_cookie_parse_fail" => StatusCode::BAD_REQUEST,
            "error_not_managing_phishing" => StatusCode::UNAUTHORIZED,
            "error_not_deleting_phishing" => StatusCode::UNAUTHORIZED,
            "error_invalid_url_from" => StatusCode::BAD_REQUEST,
            "error_invalid_url_to" => StatusCode::BAD_REQUEST,
            "error_session_expired" => StatusCode::BAD_REQUEST,
            "error_selflink_forbidden" => StatusCode::FORBIDDEN,
            "error_shortlink_forbidden" => StatusCode::FORBIDDEN,
            "error_blacklisted_link" => StatusCode::FORBIDDEN,
            "error_captcha_fail" => StatusCode::BAD_REQUEST,
            "error_unsupported_protocol" => StatusCode::BAD_REQUEST,
            "error_link_already_exists" => StatusCode::FORBIDDEN,
            "error_async" => StatusCode::INTERNAL_SERVER_ERROR,
            "error_dirtyhacker" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
