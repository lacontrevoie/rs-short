use askama::Template;
use base64::prelude::*;
use std::collections::HashMap;

use crate::database::LinkInfo;
use crate::init::{ConfGeneral, ValidLanguages, CONFIG, DEFAULT_LANGUAGE, LANG};

use actix_web::HttpRequest;

use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Debug)]
pub struct TplNotification<'a> {
    pub message: &'a str,
    pub is_valid: bool,
}

impl TplNotification<'_> {
    pub fn new(
        page: &'static str,
        message_key: &str,
        p_is_valid: bool,
        l: &ValidLanguages,
    ) -> Self {
        let tr_msg = if let Some(tr) = LANG.wait().pages[page].map.get(message_key) {
            &tr[l]
        } else {
            eprintln!("FATAL: Missing translation for key {}", message_key);
            &LANG.wait().pages[page].map["fatal_missing_translation"][l]
        };

        TplNotification {
            message: tr_msg,
            is_valid: p_is_valid,
        }
    }
}

//#[template(source = r#"{{ loc|tr(l,"desc") }}"#, ext = "txt")]
#[derive(Template)]
#[template(path = "home.html")]
pub struct HomeTemplate<'a> {
    pub loc: &'a HashMap<String, HashMap<ValidLanguages, String>>,
    pub l: &'a ValidLanguages,
    pub captcha: &'a String,
    pub notification: Option<&'a TplNotification<'a>>,
    pub linkinfo: Option<&'a LinkInfo>,
    pub config: &'static ConfGeneral,
}

#[derive(Template)]
#[template(path = "phishing.html")]
pub struct PhishingTemplate<'a> {
    pub loc: &'a HashMap<String, HashMap<ValidLanguages, String>>,
    pub l: &'a ValidLanguages,
    pub config: &'static ConfGeneral,
}

// needs cookie access for captcha purposes
pub fn gentpl_home(
    l: &ValidLanguages,
    captcha: Option<&[u8]>,
    linkinfo: Option<&LinkInfo>,
    notification: Option<&TplNotification>,
) -> String {
    if let Some(captcha_image) = captcha {
        // if it succeeds, renders the template
        HomeTemplate {
            loc: &LANG.wait().pages["home"].map,
            l,
            captcha: &BASE64_STANDARD.encode(&captcha_image),
            notification,
            linkinfo,
            config: &CONFIG.wait().general,
        }
        .render()
    } else {
        // if it fails, returns an error message
        eprintln!("FATAL: Failed to generate the captcha");
        HomeTemplate {
            loc: &LANG.wait().pages["home"].map,
            l,
            captcha: &String::from("Error"),
            notification: Some(&TplNotification::new("home", "fatal_captcha_gen", false, l)),
            linkinfo,
            config: &CONFIG.wait().general,
        }
        .render()
    }
    .expect("FATAL: Failed to render home template")
}

// determine the user language for i18n purposes
pub fn get_lang(req: &HttpRequest) -> ValidLanguages {
    try_get_lang(req).unwrap_or(DEFAULT_LANGUAGE)
}

fn try_get_lang(req: &HttpRequest) -> Option<ValidLanguages> {
    Some(ValidLanguages::from_str(
        // getting language from client header
        // taking the two first characters of the Accept-Language header,
        // in lowercase, then parsing it
        &req.headers()
            .get("Accept-Language")?
            .to_str()
            .ok()?
            .to_lowercase()[..2],
    ))
}

mod filters {
    use crate::templates::DEFAULT_LANGUAGE;
    // translation filter
    use crate::init::ValidLanguages;
    use std::collections::HashMap;

    pub fn tr(
        loc: &HashMap<String, HashMap<ValidLanguages, String>>,
        lang: &ValidLanguages,
        key: &str,
    ) -> ::askama::Result<String> {
        if let Some(s) = try_tr(loc, lang, key) {
            Ok(s)
        } else {
            // if the language is invalid or the specified key doesn't exist
            let err = format!("tr filter error! {} key, {} language", key, lang);
            eprintln!("{}", err);
            Ok(err)
        }
    }

    fn try_tr(
        loc: &HashMap<String, HashMap<ValidLanguages, String>>,
        lang: &ValidLanguages,
        key: &str,
    ) -> Option<String> {
        Some(
            loc.get(key)?
                .get(lang)
                .unwrap_or(loc.get(key)?.get(&DEFAULT_LANGUAGE)?)
                .to_string(),
        )
    }
}

// used to generate random strings for:
// - link admin panel (links.key field, 24 bytes)
// - short link names when none is specified (links.url_from field, 6 bytes)
pub fn gen_random(n_bytes: usize) -> Vec<u8> {
    // Using /dev/random to generate random bytes
    let mut r = OsRng;

    let mut my_secure_bytes = vec![0u8; n_bytes];
    r.fill_bytes(&mut my_secure_bytes);
    my_secure_bytes
}

pub fn get_ip(req: &HttpRequest) -> String {
    if let Some(v) = req.connection_info().realip_remote_addr() {
        v.to_owned()
        // do not trim the port anymore since there is
        // no port with a reverse proxy.
        // some more testing might be needed.
        /*.trim_end_matches(|c: char| c.is_numeric())
        .trim_end_matches(':')*/
    } else {
        req.connection_info()
            .realip_remote_addr()
            .expect("ERROR: Failed to get client IP.");
        eprintln!(
            "More information:\nRequest: {:?}\nConnection info: {:?}",
            req,
            req.connection_info()
        );
        panic!();
    }
}
