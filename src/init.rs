use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

pub const URL_FROM_BL_FILE: &str = "./url_from_blacklist.txt";
pub const URL_TO_BL_FILE: &str = "./url_to_blacklist.txt";
pub const URL_TO_SOFTBL_FILE: &str = "./url_to_softblacklist.txt";
pub const LANG_FILE: &str = "./lang.json";

pub const ALLOWED_PROTOCOLS: &[&str] = &[
    "http://",
    "https://",
    "dat://",
    "dweb://",
    "ipfs://",
    "ipns://",
    "ssb:",
    "gopher://",
    "xmpp:",
    "matrix:",
    "irc://",
    "news:",
    "svn://",
    "scp://",
    "ftp://",
    "ftps://",
    "ftpes://",
    "magnet:",
    "gemini://",
    "nntp://",
    "mailto:",
    "ssh://",
    "webcal:",
    "feed:",
    "rss:",
    "rtsp:",
    "file:",
    "telnet:",
    "realaudio:"
];

pub const DEFAULT_LANGUAGE: ValidLanguages = ValidLanguages::En;

pub const CAPTCHA_LETTERS: u32 = 6;

pub const CONFIG_VERSION: u8 = 2;

// initializing configuration

lazy_static! {
    pub static ref CONFIG: Config = Config::init();
}

// initializing lang.json file

lazy_static! {
    pub static ref LANG: Lang = Lang::init();
}

// initializing blacklists

lazy_static! {
    pub static ref URL_FROM_BL: Vec<String> =
        lines_from_file(URL_FROM_BL_FILE).expect("Failed to load url_from blacklist");
}

lazy_static! {
    pub static ref URL_TO_BL: Vec<String> =
        lines_from_file(URL_TO_BL_FILE).expect("Failed to load url_to blacklist");
}

lazy_static! {
    pub static ref URL_TO_SOFTBL: Vec<String> =
        lines_from_file(URL_TO_SOFTBL_FILE).expect("Failed to load url_to soft blacklist");
}

fn lines_from_file(filename: impl AsRef<Path>) -> io::Result<Vec<String>> {
    BufReader::new(File::open(filename)?).lines().collect()
}

// DEFINE VALID LANGUAGES HERE
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValidLanguages {
    En,
    Fr,
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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
    pub max_cache_size: u16,
}

#[derive(Deserialize)]
pub struct ConfPhishing {
    pub verbose_console: bool,
    pub verbose_suspicious: bool,
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

impl Config {
    pub fn init() -> Self {
        let mut conffile = File::open("config.toml").expect(
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
