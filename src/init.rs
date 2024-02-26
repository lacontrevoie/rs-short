use actix_web::cookie::Key;

use base64::prelude::*;

use once_cell::sync::OnceCell;

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;

use regex::Regex;

use crate::spam::PolicyList;
use crate::structs;

pub const CONFIG_FILE: &str = "./config.toml";
pub const LISTS_FILE: &str = "./lists.toml";
pub const LANG_FILE: &str = "./lang.json";

pub const ALLOWED_PROTOCOLS: &[&str] = &[
    "http",
    "https",
    "dat",
    "dweb",
    "ipfs",
    "ipns",
    "ssb",
    "gopher",
    "xmpp",
    "matrix",
    "irc",
    "news",
    "svn",
    "scp",
    "ftp",
    "ftps",
    "ftpes",
    "magnet",
    "gemini",
    "nntp",
    "mailto",
    "ssh",
    "webcal",
    "feed",
    "rss",
    "rtsp",
    "file",
    "telnet",
    "realaudio",
];

pub const DEFAULT_LANGUAGE: ValidLanguages = ValidLanguages::En;

pub const CAPTCHA_LETTERS: u32 = 6;

pub const CONFIG_VERSION: u8 = 3;

// initializing configuration
pub static CONFIG: OnceCell<Config> = OnceCell::new();
// initializing lang.json file
pub static LANG: OnceCell<Lang> = OnceCell::new();
// initializing policy list
pub static POLICY: OnceCell<PolicyList> = OnceCell::new();

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AllowedThemes {
    Light,
    Dark,
    Custom,
}

// Initialize RE_URL_FROM, CONFIG, LANG and POLICY.
pub fn read_config() {
    let regex = Regex::new(r#"^[^,*';?:@=&.<>#%/\\\[\]\{\}"|^~ ]{0,80}$"#)
        .expect("Failed to read NewLink url_from sanitize regular expression");
    structs::RE_URL_FROM
        .set(regex)
        .expect("could not load regex");
    CONFIG
        .set(Config::init())
        .ok()
        .expect("could not load config");
    LANG.set(Lang::init()).ok().expect("could not load langs");
    POLICY
        .set(PolicyList::init())
        .ok()
        .expect("could not load policy list");
}

// DEFINE VALID LANGUAGES HERE
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidLanguages {
    En,
    Fr,
    Hr,
    Oc,
}

// The lang codes MUST correspond to the
// Accept-Language header format.
impl ValidLanguages {
    pub fn from_str(s: &str) -> ValidLanguages {
        match s.to_lowercase().as_str() {
            "en" => ValidLanguages::En,
            "fr" => ValidLanguages::Fr,
            "hr" => ValidLanguages::Hr,
            "oc" => ValidLanguages::Oc,
            _ => DEFAULT_LANGUAGE,
        }
    }

    /*
    pub fn _get_list() -> Vec<&'static str> {
        vec!["En", "Fr"]
    }*/
}

impl fmt::Display for ValidLanguages {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for AllowedThemes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Lang {
    pub pages: HashMap<String, LangChild>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct LangChild {
    pub template: String,
    pub map: HashMap<String, HashMap<ValidLanguages, String>>,
}

impl Lang {
    pub fn init() -> Self {
        let mut file = File::open(LANG_FILE).expect("Lang.init(): Can't open lang file!!");
        let mut data = String::new();
        file.read_to_string(&mut data)
            .expect("Lang.init(): Can't read lang file!!");
        let json: Lang =
            serde_json::from_str(&data).expect("Lang.init(): lang file JSON parse fail!!");
        json
    }
}

// config.toml settings

#[derive(Serialize, Deserialize)]
pub struct ConfGeneral {
    pub listening_address: String,
    pub database_path: String,
    pub instance_hostname: String,
    pub hoster_name: String,
    pub hoster_hostname: String,
    pub hoster_tos: String,
    pub contact: String,
    pub theme: AllowedThemes,
    pub captcha_difficulty: u8,
    pub cookie_key: String,
}

#[derive(Deserialize)]
pub struct ConfPhishing {
    pub verbose_console: bool,
    pub verbose_suspicious: bool,
    pub verbose_level: VerboseLevel,
    pub suspicious_click_count: usize,
    pub suspicious_click_timeframe: u8,
    pub phishing_password: String,
}

#[derive(Deserialize)]
pub struct Config {
    pub config_version: u8,
    pub general: ConfGeneral,
    pub phishing: ConfPhishing,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerboseLevel {
    Info,
    Notice,
    Warn,
    Crit,
}

impl Config {
    pub fn init() -> Self {
        let mut conffile = File::open(CONFIG_FILE).expect(
            r#"Config file config.toml not found.
                    Please create it using config.toml.sample."#,
        );
        let mut confstr = String::new();
        conffile
            .read_to_string(&mut confstr)
            .expect("Couldn't read config to string");
        toml::from_str(&confstr).unwrap()
    }

    pub fn check(&self) {
        // check config version
        if self.config_version != CONFIG_VERSION {
            eprintln!("Your configuration file is obsolete! Please update it using config.toml.sample and update its version to {}.", CONFIG_VERSION);
            panic!();
        }

        // check for default values
        Self::check_default(
            "instance_hostname",
            &self.general.instance_hostname,
            "s.example.com",
            true,
        );
        Self::check_default(
            "hoster_name",
            &self.general.hoster_name,
            "ExampleSoft",
            false,
        );
        Self::check_default(
            "hoster_hostname",
            &self.general.hoster_hostname,
            "example.com",
            false,
        );
        Self::check_default(
            "hoster_tos",
            &self.general.hoster_tos,
            "https://example.com/ToS",
            false,
        );
        Self::check_default(
            "contact",
            &self.general.contact,
            "mailto:contact@example.com",
            false,
        );
        Self::check_default("cookie_key", &self.general.cookie_key, "CHANGE ME", true);
        Self::check_default(
            "phishing_password",
            &self.phishing.phishing_password,
            "CHANGE ME",
            true,
        );

        // check cookie key and phishing password
        if self.general.cookie_key.len() < 88 {
            eprintln!("Your cookie key is shorter than 64 bits. Please refer to the config.toml.sample file to know how to generate a cookie key with the proper length.");
            panic!();
        }

        if self.general.cookie_key.len() < 16 {
            eprintln!("Your phishing password is shorter than 16 characters. You must increase it for security reasons.");
            panic!();
        }
    }

    fn check_default(name: &str, current: &str, default: &str, is_blocking: bool) {
        if current == default {
            eprintln!(
                "Your configuration parameter {} is set to its default value ({}).",
                name, current
            );
            if is_blocking {
                eprintln!("You must change it in order to proceed.");
                panic!();
            }
        }
    }
}

pub fn get_cookie_key(cookie_key: &str) -> Key {
    let key = BASE64_STANDARD
        .decode(cookie_key)
        .expect("Failed to read cookie key!");
    Key::from(&key[..64])
}
