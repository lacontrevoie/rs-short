use actix_session::Session;
use actix_web::http::Method;
use actix_web::HttpResponseBuilder;
use actix_web::{error, http::StatusCode};
use actix_web::{HttpRequest, HttpResponse, Result};
use askama::Template;
use std::fmt;

use crate::init::{ValidLanguages, VerboseLevel};
use crate::spam::cookie_captcha_set;
use crate::init::{LANG, CONFIG};
use crate::templates::{gentpl_home, get_lang, get_ip, TplNotification, PhishingTemplate};

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    CritDbPool,                 // => StatusCode::INTERNAL_SERVER_ERROR,
    CritDbFail,                 // => StatusCode::INTERNAL_SERVER_ERROR,
    CritLinkDeleteDbFail,       // => StatusCode::INTERNAL_SERVER_ERROR,
    CritAwaitFail,              // => StatusCode::INTERNAL_SERVER_ERROR,
    WarnBadServerAdminKey,      // => StatusCode::UNAUTHORIZED,
    WarnShortlinkForbidden,     // => StatusCode::FORBIDDEN,
    WarnBlocklistedLink,        // => StatusCode::FORBIDDEN,
    WarnCaptchaFail,            // => StatusCode::BAD_REQUEST,
    NoticeUnsupportedProtocol,  // => StatusCode::BAD_REQUEST,
    NoticeLinkAlreadyExists,    // => StatusCode::FORBIDDEN,
    NoticeInvalidKey,           // => StatusCode::UNAUTHORIZED,
    NoticeNotManagingPhishing,  // => StatusCode::UNAUTHORIZED,
    NoticeNotDeletingPhishing,  // => StatusCode::UNAUTHORIZED,
    NoticeCookieParseFail,      // => StatusCode::BAD_REQUEST,
    InfoLinkNotFound,           // => StatusCode::NOT_FOUND,
    InfoInvalidUrlFrom,         // => StatusCode::BAD_REQUEST,
    InfoInvalidUrlTo,           // => StatusCode::BAD_REQUEST,
    InfoInvalidLink,            // => StatusCode::NOT_FOUND,
    InfoSessionExpired,         // => StatusCode::BAD_REQUEST,
    InfoSelflinkForbidden,      // => StatusCode::FORBIDDEN,
    InfoNotFound,               // => StatusCode::NOT_FOUND,
    InfoPhishingLinkReached,    // => StatusCode::GONE,
}


// 404 handler
pub async fn default_handler(
    req_method: Method,
    req: HttpRequest,
    s: Session,
) -> Result<HttpResponse, ShortCircuit> {
    match req_method {
        Method::GET => {
            let captcha = cookie_captcha_set(&s);

            Err(crash(ErrorKind::InfoNotFound, "link not found".into(), get_ip(&req), get_lang(&req), captcha))
        }
        _ => Ok(HttpResponse::MethodNotAllowed().finish()),
    }
}

pub fn crash(
    error_kind: ErrorKind,
    error_msg: String,
    ip: String,
    lang: ValidLanguages,
    captcha: Option<Vec<u8>>,
) -> ShortCircuit {
    ShortCircuit {
        error_kind,
        error_msg,
        ip,
        lang,
        captcha,
    }
}

#[derive(Debug)]
pub struct ShortCircuit {
    pub error_kind: ErrorKind,
    pub error_msg: String,
    pub ip: String,
    pub lang: ValidLanguages,
    pub captcha: Option<Vec<u8>>,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for ShortCircuit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} - {:?}", self.error_kind, self.error_msg)
    }
}

impl ShortCircuit {
    fn print_format(&self) {
        eprintln!("[{}] {}: {}", self.ip, self.error_kind, self.error_msg);
    }

    fn print_error(&self) {
        match &CONFIG.phishing.verbose_level {
            VerboseLevel::Crit => {
                if self.error_kind.is_critical() {
                    self.print_format();
                }
            },
            VerboseLevel::Warn => {
                if self.error_kind.is_critical() || self.error_kind.is_warning() {
                    self.print_format();
                }
            }
            VerboseLevel::Notice => {
                if self.error_kind.is_critical() || self.error_kind.is_warning() || self.error_kind.is_notice() {
                    self.print_format();
                }
            }
            VerboseLevel::Info => self.print_format(),
        }

    }
}

impl error::ResponseError for ShortCircuit {

    fn error_response(&self) -> HttpResponse {
        // print to console
        self.print_error();

        // display the error message.
        // special case for the PhishingLinkReached error
        match self.error_kind {
            ErrorKind::InfoPhishingLinkReached => {
                HttpResponseBuilder::new(self.status_code())
                    .content_type("text/html").body(
                    PhishingTemplate {
                        loc: &LANG.pages["phishing"].map,
                        l: &self.lang,
                        config: &CONFIG.general,
                    }
                    .render()
                    .expect("FATAL: Failed to render phishing template")
                )
            },
            _ => {
                let tpl = TplNotification::new("home", &format!("{}", self.error_kind), false, &self.lang);

                HttpResponseBuilder::new(self.status_code())
                    .content_type("text/html")
                    .body(gentpl_home(
                        &self.lang,
                        self.captcha.as_deref(),
                        None,
                        Some(&tpl),
                    ))
            }
        }
    }

    fn status_code(&self) -> StatusCode {
        match self.error_kind {
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ErrorKind {
    /*pub fn is_info(&self) -> bool {
        matches!(
            self,
            ErrorKind::InfoLinkNotFound
            | ErrorKind::InfoInvalidUrlFrom
            | ErrorKind::InfoInvalidUrlTo
            | ErrorKind::InfoInvalidLink
            | ErrorKind::InfoSessionExpired
            | ErrorKind::InfoSelflinkForbidden
            | ErrorKind::InfoNotFound
            | ErrorKind::InfoPhishingLinkReached
        )
    }*/
    pub fn is_notice(&self) -> bool {
        matches!(
            self,
            ErrorKind::NoticeCookieParseFail
            | ErrorKind::NoticeNotDeletingPhishing
            | ErrorKind::NoticeNotManagingPhishing
            | ErrorKind::NoticeInvalidKey
            | ErrorKind::NoticeLinkAlreadyExists
            | ErrorKind::NoticeUnsupportedProtocol
        )
    }
    pub fn is_warning(&self) -> bool {
        matches!(
            self,
            ErrorKind::WarnCaptchaFail
            | ErrorKind::WarnBlocklistedLink
            | ErrorKind::WarnShortlinkForbidden
            | ErrorKind::WarnBadServerAdminKey
        )
    }
    
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            ErrorKind::CritAwaitFail
            | ErrorKind::CritLinkDeleteDbFail
            | ErrorKind::CritDbFail
            | ErrorKind::CritDbPool
        )
    }
}
