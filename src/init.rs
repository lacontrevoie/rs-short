use actix_web::cookie::Key;

use once_cell::sync::Lazy;

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;

use crate::spam::PolicyList;

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
pub static CONFIG: Lazy<Config> = Lazy::new(|| Config::init());
// initializing lang.json file
pub static LANG: Lazy<Lang> = Lazy::new(|| Lang::init());
// initializing policy list
pub static POLICY: Lazy<PolicyList> = Lazy::new(|| PolicyList::init());

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
    pub theme: String,
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
    pub fn check_version(&self) {
        if self.config_version != CONFIG_VERSION {
            eprintln!("Your configuration file is obsolete! Please update it using config.toml.sample and update its version to {}.", CONFIG_VERSION);
            panic!();
        }
    }
}

pub fn get_cookie_key(cookie_key: &str) -> Key {
    let key = base64::decode(cookie_key).expect("Failed to read cookie key!");
    Key::from(&key[..64])
}
