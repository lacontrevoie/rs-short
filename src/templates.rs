// std uses
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

// Rocket uses
use rocket_contrib::templates::handlebars::{Helper, Handlebars, Context, RenderContext, HelperResult, Output};
use rocket::Outcome::*;
use rocket::Request;
use rocket::request::{self, FromRequest};

// captcha uses
use captcha::Captcha;
use captcha::filters::{Noise, Wave, Grid};

// rand uses
use rand::Rng;

// local uses
use crate::link::LinkInfo;
use crate::config::*;

pub const LANG_FILE: &str = "./lang.json";
pub const DEFAULT_LANGUAGE: ValidLanguages = ValidLanguages::Fr;

// DEFINE VALID LANGUAGES HERE
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidLanguages {
    En, Fr,
}

// The lang codes MUST correspond to the
// Accept-Language header format.
impl ValidLanguages {
    pub fn from_str(s: &str) -> ValidLanguages {
        match s.to_lowercase().as_str() {
            "en" => ValidLanguages::En,
            "fr" => ValidLanguages::Fr,
            _ => DEFAULT_LANGUAGE,
        }
    }
    pub fn get_list() -> Vec<&'static str> {
        // ALSO DEFINE VALID LANGUAGES HERE AND JUST ABOVE
        vec!["En", "Fr"]
    }
}

impl fmt::Display for ValidLanguages {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct LangHeader(pub ValidLanguages);

impl<'a, 'r> FromRequest<'a, 'r> for LangHeader {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, ()> {
        match request.clone().headers().get_one("Accept-Language") {
            Some(s) => {
                let mut s_s = String::from(s);
                s_s.to_lowercase();
                s_s.truncate(2);
                match s_s.len() < 2 {
                    true => Success(LangHeader(DEFAULT_LANGUAGE)),
                    false => Success(LangHeader(ValidLanguages::from_str(s_s.as_str()))),
                }
            }
            None => Success(LangHeader(DEFAULT_LANGUAGE))
        }
    }
}

#[derive(Debug)]
pub struct IPAddress(pub IpAddr);

impl<'a, 'r> FromRequest<'a, 'r> for IPAddress {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, ()> {
        // if we can't read the client IP address, defaults to unspecified
        // to avoid panic. Also writes an error in stdout.
        // Let's not forget to consider that "feature" in case IP-based
        // features gets implemented someday.
        let ipaddr = request.client_ip()
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        if ipaddr.is_unspecified() {
            eprintln!("WARN: Failed to read client IP address");
        }
        Success(IPAddress(ipaddr))
    }
}

// Generic Template Context
// That's not like there are so many pages anyway
#[derive(Serialize)]
pub struct GeneralContext {
    // l10n data for the page
    pub loc: LangChild,
    // l is the user's language
    pub l: ValidLanguages,
    // the captcha.png as base64
    pub captcha: Option<String>,
    // the parent template - if needed.
    pub parent: &'static str,
    // if form_result is set, a notification will be displayed.
    // the notification color will be green or red depending on form_is_valid.
    pub form_result: Option<String>,
    pub form_is_valid: bool,
    // for the link admin page (access with key) + link creation
    pub linkinfo: Option<LinkInfo>,
    // service hoster address, constant defined in main.
    pub config: &'static ConfGeneral,
}

#[derive(Serialize, Deserialize)]
pub struct Lang {
    pub pages: HashMap<String, LangChild>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LangChild {
    pub template: String,
    pub lang: HashMap<String, HashMap<ValidLanguages, String>>
}

impl Lang {
    pub fn init() -> Self {
        let mut file = File::open(LANG_FILE)
            .expect("Lang.init(): Can't open lang file!!");
        let mut data = String::new();
        file.read_to_string(&mut data)
            .expect("Lang.init(): Can't read lang file!!");
        let json: Lang = serde_json::from_str(&data)
            .expect("Lang.init(): lang file JSON parse fail!!");
        json
    }
}

pub fn tr_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut dyn Output,
    ) -> HelperResult {

    if let Some(loc_key) = h.param(0) {
        if let Some(lang) = h.param(1) {
            let selected_lang = ValidLanguages::from_str(
                lang.value().as_str()
                .unwrap_or(&format!("{}", DEFAULT_LANGUAGE)));

            // in case we fail to extract data for default language, we display
            // "TR_Error" instead of panicking.
            let error = json!("TR_Error");
            let loc_value = loc_key.value().get(format!("{}", selected_lang))
                .unwrap_or(loc_key.value().get(format!("{}", DEFAULT_LANGUAGE))
                           .unwrap_or(&error));

            if loc_value == "TR_Error" {
                eprintln!("tr_helper: TR_Error at {:?} for language {}",
                          loc_key, selected_lang);
            }

            out.write(loc_value.as_str()
                      .expect("tr_helper: failed to convert loc_value to &str (text)"))?;
        }
    }
    Ok(())
}


pub fn gen_captcha() -> Option<(String, Vec<u8>)> {

    let mut rng = rand::thread_rng();

    let mut captcha = Captcha::new();
    captcha
        .add_chars(6);
    if CONFIG.general.captcha_difficulty >= 1 {
        captcha.apply_filter(Noise::new(0.1));

    }
    if CONFIG.general.captcha_difficulty >= 2 {
        captcha
            .apply_filter(Wave::new(rng.gen_range(1, 4) as f64, rng.gen_range(6, 13) as f64).horizontal())
            .apply_filter(Wave::new(rng.gen_range(1, 4) as f64, rng.gen_range(6, 13) as f64).vertical());
    }
    if CONFIG.general.captcha_difficulty >= 3 {
        captcha.apply_filter(Grid::new(rng.gen_range(15, 25), rng.gen_range(15, 25)));

    }
    if CONFIG.general.captcha_difficulty >= 4 {
        captcha
            .apply_filter(Wave::new(rng.gen_range(1, 4) as f64, rng.gen_range(5, 9) as f64).horizontal())
            .apply_filter(Wave::new(rng.gen_range(1, 4) as f64, rng.gen_range(5, 9) as f64).vertical());
    }
    if CONFIG.general.captcha_difficulty >= 5 {
        captcha
            .apply_filter(Wave::new(rng.gen_range(1, 4) as f64, rng.gen_range(6, 13) as f64).horizontal())
            .apply_filter(Noise::new(0.1));
    }

    captcha.view(250, 100)
        .as_tuple()
}
