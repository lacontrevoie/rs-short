use actix_web::http::Uri;
use chrono::Duration;
use chrono::{NaiveDateTime, Utc};
use regex::Regex;

use crate::error_handlers::{throw, ErrorInfo, ErrorKind};
use crate::init::ALLOWED_PROTOCOLS;

lazy_static! {
    static ref RE_URL_FROM: Regex = Regex::new(r#"^[^,*';?:@=&.<>#%/\\\[\]\{\}"|^~ ]{0,80}$"#)
        .expect("Failed to read NewLink url_from sanitize regular expression");
}

#[derive(Serialize, Deserialize)]
pub struct NewLink {
    pub url_from: String,
    pub url_to: String,
    pub captcha: String,
}

impl NewLink {
    // ---------------------------------------------------------------
    // url_from is the custom text set for the link.
    // A valid url_from value must contain a maximum of 50 characters.
    // It MUST NOT contain reserved characters or dot '.' character.
    // ---------------------------------------------------------------
    // url_to is the link being shortened.
    // A valid url_to must contain a maximum of 4096 characters.
    // It must be parsed successfully by the url crate.
    // ---------------------------------------------------------------
    // captcha contains the captcha result.
    // A valid captcha must be CAPTCHA_LETTERS characters long.
    // It must match with the captcha answer in cookies.
    // All comparisons are lowercase.
    // ---------------------------------------------------------------
    pub fn validate(&self, captcha_key: &(NaiveDateTime, String)) -> Result<Uri, ErrorInfo> {
        // attempt to parse url_to as a valid URL
        let uri: Uri = self.url_to.parse().map_err(|_| {
            throw(
                ErrorKind::InfoInvalidUrlTo,
                format!("couldn’t parse as Uri: {}", self.url_to),
            )
        })?;

        // check the scheme
        match uri.scheme_str() {
            Some(s) => {
                // check the allowed protocols
                // if the uri scheme isn’t on the list, early return
                if ALLOWED_PROTOCOLS.iter().any(|&p| p == s) {
                    Ok(())
                } else {
                    Err(throw(
                        ErrorKind::NoticeUnsupportedProtocol,
                        format!("invalid protocol: {}", s),
                    ))
                }
            }
            None => Err(throw(
                ErrorKind::InfoInvalidUrlTo,
                format!("no scheme in URL: {}", self.url_to),
            )),
        }?;

        // check the host
        if uri.host().is_none() {
            return Err(throw(
                ErrorKind::InfoInvalidUrlTo,
                format!("no host found in URL: {}", self.url_from),
            ));
        }

        if self.url_from.len() > 50 || !RE_URL_FROM.is_match(&self.url_from) {
            Err(throw(
                ErrorKind::InfoInvalidUrlFrom,
                format!("invalid shortcut name: {}", self.url_from),
            ))
        } else if self.url_to.len() > 4096 {
            Err(throw(
                ErrorKind::InfoInvalidUrlTo,
                format!("too long URL: {}", self.url_to),
            ))
        } else if captcha_key.0 < (Utc::now().naive_utc() - Duration::minutes(30)) {
            Err(throw(
                ErrorKind::InfoSessionExpired,
                "captcha session expired".into(),
            ))
        } else if self.captcha.to_lowercase().trim() != captcha_key.1.to_lowercase().trim() {
            Err(throw(
                ErrorKind::WarnCaptchaFail,
                format!(
                    "captcha failed: {} | {}",
                    self.captcha.to_lowercase().trim(),
                    captcha_key.1.to_lowercase().trim()
                ),
            ))
        } else {
            Ok(uri)
        }
    }
}
