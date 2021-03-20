use actix_web::HttpRequest;
use chrono::Duration;
use chrono::{NaiveDateTime, Utc};
use regex::Regex;
use url::Url;

use crate::init::ValidLanguages;
use crate::templates::get_ip;
use crate::templates::TplNotification;

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
    pub fn validate(
        &self,
        l: &ValidLanguages,
        req: &HttpRequest,
        captcha_key: (NaiveDateTime, String),
    ) -> Result<(), TplNotification> {
        lazy_static! {
            static ref RE_URL_FROM: Regex = Regex::new(r#"^[^,*';?:@=&.<>#%/\\\[\]\{\}"|^~ ]{0,80}$"#)
                .expect("Failed to read NewLink url_from sanitize regular expression");
        }
        if self.url_from.len() > 50 || !RE_URL_FROM.is_match(&self.url_from) {
            Err(TplNotification::new(
                "home",
                "error_invalid_url_from",
                false,
                l,
            ))
        } else if self.url_to.len() > 4096 || Url::parse(&self.url_to).is_err() {
            Err(TplNotification::new(
                "home",
                "error_invalid_url_to",
                false,
                l,
            ))
        } else if captcha_key.0 < (Utc::now().naive_utc() - Duration::minutes(30)) {
            Err(TplNotification::new(
                "home",
                "error_session_expired",
                false,
                l,
            ))
        } else if self.captcha.to_lowercase() != captcha_key.1.to_lowercase() {
            println!(
                "INFO: [{}] failed the captcha (input: \"{}\", answer: \"{}\").",
                get_ip(req),
                self.captcha,
                captcha_key.1
            );
            Err(TplNotification::new("home", "error_captcha_fail", false, l))
        } else {
            Ok(())
        }
    }
}
