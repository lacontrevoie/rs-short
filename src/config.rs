use std::fs::File;
use std::io::Read;
use diesel::SqliteConnection;

lazy_static! {
    pub static ref CONFIG: Config = Config::init();
}

pub const BANNED_URL_FROM: &str = "./banned_url_from.list";
pub const BANNED_URL_TO: &str = "./banned_url_to.list";

pub const RE_URL_FROM: &str = r"^[^;\/?:@=&.<>#%\[\]\{\}|\\\^\~\ ]{2,80}$";

#[database("sqlite_database")]
pub struct DbConn(SqliteConnection);

#[derive(Clone)]
pub struct BannedUrlFrom(pub Vec<String>);

#[derive(Clone)]
pub struct BannedUrlTo(pub Vec<String>);

// config.toml settings

#[derive(Serialize, Deserialize)]
pub struct ConfGeneral {
    pub instance_hostname: String,
    pub hoster_hostname: String,
    pub hoster_tos: String,
    pub contact: String,
    pub theme: String,
    pub captcha_difficulty: u8,
}

#[derive(Deserialize)]
pub struct ConfPhishing {
    pub verbose_console: bool,
    pub verbose_suspicious: bool,
    pub suspicious_click_times: u8,
    pub phishing_password: String,
}

#[derive(Deserialize)]
pub struct Config {
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
}
