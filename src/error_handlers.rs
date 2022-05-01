use actix_session::Session;
use actix_web::http::Method;
use actix_web::HttpResponseBuilder;
use actix_web::{error, http::StatusCode};
use actix_web::{HttpRequest, HttpResponse, Result};
use askama::Template;
use std::fmt;

use crate::init::{ValidLanguages, VerboseLevel};
use crate::init::{CONFIG, LANG};
use crate::spam::cookie_captcha_set;
use crate::templates::{gentpl_home, get_ip, get_lang, PhishingTemplate, TplNotification};

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    CritDbPool,
    CritDbFail,
    CritLinkDeleteDbFail,
    CritAwaitFail,
    WarnBadServerAdminKey,
    WarnBlockedLinkShortener,
    WarnBlockedLinkSpam,
    WarnBlockedLinkFreehost,
    WarnBlockedName,
    WarnCaptchaFail,
    NoticeUnsupportedProtocol,
    NoticeLinkAlreadyExists,
    NoticeInvalidKey,
    NoticeNotManagingPhishing,
    NoticeNotDeletingPhishing,
    NoticeCookieParseFail,
    InfoLinkNotFound,
    InfoInvalidUrlFrom,
    InfoInvalidUrlTo,
    InfoInvalidLink,
    InfoSessionExpired,
    InfoSelflinkForbidden,
    InfoNotFound,
    InfoPhishingLinkReached,
}

#[derive(Debug)]
pub struct ErrorInfo {
    pub kind: ErrorKind,
    pub msg: String,
}

// 404 handler
pub async fn default_handler(
    req_method: Method,
    req: HttpRequest,
    s: Session,
) -> Result<HttpResponse, ShortCircuit> {
    match req_method {
        Method::GET => Err(crash(
            throw(ErrorKind::InfoNotFound, "link not found".into()),
            pass(&req, &s),
        )),
        _ => Ok(HttpResponse::MethodNotAllowed().finish()),
    }
}

// easily create an ErrorInfo to throw an error
pub fn throw(kind: ErrorKind, msg: String) -> ErrorInfo {
    ErrorInfo { kind, msg }
}

// prepare all the required information to throw an error
pub fn pass(req: &HttpRequest, s: &Session) -> RequestInfo {
    RequestInfo {
        ip: get_ip(req),
        lang: get_lang(req),
        captcha: cookie_captcha_set(s),
    }
}

// throw the actual error with crash(throw(…), pass(…))
pub fn crash(error: ErrorInfo, req: RequestInfo) -> ShortCircuit {
    ShortCircuit { error, req }
}

#[derive(Debug)]
pub struct RequestInfo {
    pub ip: String,
    pub lang: ValidLanguages,
    pub captcha: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ShortCircuit {
    pub error: ErrorInfo,
    pub req: RequestInfo,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for ShortCircuit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} - {:?}", self.error.kind, self.error.msg)
    }
}

impl ShortCircuit {
    fn print_format(&self) {
        eprintln!("[{}] {}: {}", self.req.ip, self.error.kind, self.error.msg);
    }

    fn print_error(&self) {
        match &CONFIG.phishing.verbose_level {
            VerboseLevel::Crit => {
                if self.error.kind.is_critical() {
                    self.print_format();
                }
            }
            VerboseLevel::Warn => {
                if self.error.kind.is_critical() || self.error.kind.is_warning() {
                    self.print_format();
                }
            }
            VerboseLevel::Notice => {
                if self.error.kind.is_critical()
                    || self.error.kind.is_warning()
                    || self.error.kind.is_notice()
                {
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
        match self.error.kind {
            ErrorKind::InfoPhishingLinkReached => HttpResponseBuilder::new(self.status_code())
                .content_type("text/html")
                .body(
                    PhishingTemplate {
                        loc: &LANG.pages["phishing"].map,
                        l: &self.req.lang,
                        config: &CONFIG.general,
                    }
                    .render()
                    .expect("FATAL: Failed to render phishing template"),
                ),
            _ => {
                let tpl = TplNotification::new(
                    "home",
                    &format!("{}", self.error.kind),
                    false,
                    &self.req.lang,
                );

                HttpResponseBuilder::new(self.status_code())
                    .content_type("text/html")
                    .body(gentpl_home(
                        &self.req.lang,
                        self.req.captcha.as_deref(),
                        None,
                        Some(&tpl),
                    ))
            }
        }
    }

    fn status_code(&self) -> StatusCode {
        match &self.error.kind {
            ErrorKind::CritDbPool
            | ErrorKind::CritDbFail
            | ErrorKind::CritLinkDeleteDbFail
            | ErrorKind::CritAwaitFail => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::WarnBadServerAdminKey
            | ErrorKind::NoticeInvalidKey
            | ErrorKind::NoticeNotManagingPhishing
            | ErrorKind::NoticeNotDeletingPhishing => StatusCode::UNAUTHORIZED,
            ErrorKind::WarnBlockedLinkShortener
            | ErrorKind::WarnBlockedLinkSpam
            | ErrorKind::WarnBlockedLinkFreehost
            | ErrorKind::WarnBlockedName
            | ErrorKind::NoticeLinkAlreadyExists
            | ErrorKind::InfoSelflinkForbidden => StatusCode::FORBIDDEN,
            ErrorKind::WarnCaptchaFail
            | ErrorKind::NoticeUnsupportedProtocol
            | ErrorKind::NoticeCookieParseFail
            | ErrorKind::InfoInvalidUrlFrom
            | ErrorKind::InfoInvalidUrlTo
            | ErrorKind::InfoSessionExpired => StatusCode::BAD_REQUEST,
            ErrorKind::InfoLinkNotFound | ErrorKind::InfoInvalidLink | ErrorKind::InfoNotFound => {
                StatusCode::NOT_FOUND
            }
            ErrorKind::InfoPhishingLinkReached => StatusCode::GONE,
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
                | ErrorKind::WarnBlockedLinkFreehost
                | ErrorKind::WarnBlockedLinkShortener
                | ErrorKind::WarnBlockedLinkSpam
                | ErrorKind::WarnBlockedName
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
