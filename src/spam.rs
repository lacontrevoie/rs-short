// "captcha" was taken by the actual crate, so...
// named it "spam".

use actix_session::Session;
use actix_web::web;

use actix_web::http::Uri;
use captcha::filters::{Grid, Noise, Wave};
use captcha::Captcha;
use chrono::Duration;
use chrono::{NaiveDateTime, Utc};
use rand::Rng;
use regex::Regex;
use std::fs::File;
use std::io::Read;

use crate::database::LinkInfo;
use crate::error_handlers::{throw, ErrorInfo, ErrorKind};
use crate::init::{CAPTCHA_LETTERS, CONFIG, LISTS_FILE};
use crate::SuspiciousWatcher;

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistCategory {
    Shortener,
    Freehost,
    Spam,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistMatching {
    #[serde(rename = "full-uri")]
    FullUri,
    Host,
    Port,
    Authority,
    Path,
    Query,
}

#[derive(Deserialize)]
pub struct PolicyList {
    pub names: PolicyListNames,
    pub urls: PolicyListURLs,
}

#[derive(Deserialize)]
pub struct PolicyListNames {
    pub allowlist: Vec<AllowEntry>,
    pub blocklist: Vec<BlockEntryName>,
}

#[derive(Deserialize)]
pub struct PolicyListURLs {
    pub allowlist: Vec<AllowEntry>,
    pub blocklist: Vec<BlockEntryURL>,
}

#[derive(Deserialize, Debug)]
pub struct AllowEntry {
    #[serde(with = "serde_regex")]
    pub expr: Regex,
}

#[derive(Deserialize)]
pub struct BlockEntryName {
    #[serde(with = "serde_regex")]
    pub expr: Regex,
    pub category: BlocklistCategory,
}

#[derive(Deserialize)]
pub struct BlockEntryURL {
    #[serde(with = "serde_regex")]
    pub expr: Regex,
    pub category: BlocklistCategory,
    pub matching: Option<BlocklistMatching>,
}

impl PolicyList {
    pub fn init() -> Self {
        let mut listfile = File::open(LISTS_FILE)
            .expect("Policy list file lists.toml not found. Please create it.");
        let mut liststr = String::new();
        listfile
            .read_to_string(&mut liststr)
            .expect("Couldn't read listfile to string");
        toml::from_str(&liststr).unwrap()
    }

    pub fn is_allowlisted(&self, url_from: &str, url_to: &str) -> bool {
        self.urls.allowlist.iter().any(|r| r.expr.is_match(&url_to.to_lowercase()))
        || self.names.allowlist.iter().any(|r| r.expr.is_match(&url_from.to_lowercase()))
    }

    pub fn blocklist_check_from(&self, url_from: &str) -> Result<(), ErrorInfo> {
        if let Some(bl_entry) = self
            .names
            .blocklist
            .iter()
            .find(|&r| r.expr.is_match(&url_from.to_lowercase()))
        {
            Err(throw(
                bl_entry.errkind(),
                format!("shortcut name blocklisted: {}", url_from),
            ))
        } else {
            Ok(())
        }
    }

    pub fn blocklist_check_to(&self, uri: &Uri) -> Result<(), ErrorInfo> {
        for bl_entry in &self.urls.blocklist {
            match bl_entry.matching {
                Some(BlocklistMatching::Host) | None => {
                    // host string already checked in parent function
                    if bl_entry.expr.is_match(&uri.host().unwrap().to_lowercase()) {
                        return Err(throw(
                            bl_entry.errkind(),
                            format!("URL blocklisted [host]: {}", uri),
                        ));
                    }
                }
                Some(BlocklistMatching::FullUri) => {
                    if bl_entry.expr.is_match(&uri.to_string().to_lowercase()) {
                        return Err(throw(
                            bl_entry.errkind(),
                            format!("URL blocklisted [full-uri]: {}", uri),
                        ));
                    }
                }
                Some(BlocklistMatching::Port) => {
                    if let Some(up) = uri.port() {
                        if bl_entry.expr.is_match(&up.as_str().to_lowercase()) {
                            return Err(throw(
                                bl_entry.errkind(),
                                format!("URL blocklisted [port]: {}", uri),
                            ));
                        }
                    }
                }
                Some(BlocklistMatching::Authority) => {
                    if let Some(ua) = uri.authority() {
                        if bl_entry.expr.is_match(&ua.as_str().to_lowercase()) {
                            return Err(throw(
                                bl_entry.errkind(),
                                format!("URL blocklisted [authority]: {}", uri),
                            ));
                        }
                    }
                }
                Some(BlocklistMatching::Path) => {
                    if bl_entry.expr.is_match(&uri.path().to_lowercase()) {
                        return Err(throw(
                            bl_entry.errkind(),
                            format!("URL blocklisted [path]: {}", uri),
                        ));
                    }
                }
                Some(BlocklistMatching::Query) => {
                    if let Some(uq) = uri.query() {
                        if bl_entry.expr.is_match(&uq.to_lowercase()) {
                            return Err(throw(
                                bl_entry.errkind(),
                                format!("URL blocklisted [query]: {}", uri),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl BlockEntryName {
    pub fn errkind(&self) -> ErrorKind {
        // I see no point on writing a match for now
        ErrorKind::WarnBlockedName
    }
}

impl BlockEntryURL {
    pub fn errkind(&self) -> ErrorKind {
        match self.category {
            BlocklistCategory::Shortener => ErrorKind::WarnBlockedLinkShortener,
            BlocklistCategory::Freehost => ErrorKind::WarnBlockedLinkFreehost,
            BlocklistCategory::Spam => ErrorKind::WarnBlockedLinkSpam,
        }
    }
}

pub fn gen_captcha() -> Option<(String, Vec<u8>)> {
    let mut rng = rand::thread_rng();

    let mut captcha = Captcha::new();
    captcha.add_chars(CAPTCHA_LETTERS);

    for diff in 1..=CONFIG.general.captcha_difficulty {
        match diff {
            1 => captcha.apply_filter(Noise::new(0.1)),
            2 => captcha
                .apply_filter(
                    Wave::new(f64::from(rng.gen_range(1..4)), f64::from(rng.gen_range(6..13))).horizontal(),
                )
                .apply_filter(
                    Wave::new(f64::from(rng.gen_range(1..4)), f64::from(rng.gen_range(6..13))).vertical(),
                ),
            3 => captcha.apply_filter(Grid::new(rng.gen_range(15..25), rng.gen_range(15..25))),
            4 => captcha
                .apply_filter(
                    Wave::new(f64::from(rng.gen_range(1..4)), f64::from(rng.gen_range(5..9))).horizontal(),
                )
                .apply_filter(
                    Wave::new(f64::from(rng.gen_range(1..4)), f64::from(rng.gen_range(5..9))).vertical(),
                ),
            5 => captcha
                .apply_filter(
                    Wave::new(f64::from(rng.gen_range(1..4)), f64::from(rng.gen_range(6..13))).horizontal(),
                )
                .apply_filter(Noise::new(0.1)),
            _ => break,
        };
    }

    captcha.view(250, 100).as_tuple()
}

// Generates a captcha and sets the cookie
// containing the answer and current date
// Returns the captcha image as a Vec<u8>.
pub fn cookie_captcha_set(s: &Session) -> Option<Vec<u8>> {
    let captcha = gen_captcha()?;
    s.insert(
        "captcha-key",
        format!("{}|{}", Utc::now().naive_utc().format("%s"), captcha.0),
    )
    .ok()?;
    Some(captcha.1)
}

// Gets the cookie and parses datetime & captcha answer.
// returning a tuple (DateTime, captcha_answer)
pub fn cookie_captcha_get(s: &Session) -> Option<(NaiveDateTime, String)> {
    // getting cookie (it *must* exist)
    let cookie: String = s.get("captcha-key").ok()??;

    // splitting (date|captcha_answer)
    let cookie_split: Vec<&str> = cookie.split('|').collect();

    Some((
        NaiveDateTime::parse_from_str(cookie_split.first()?, "%s").ok()?,
        (*cookie_split.get(1)?).to_string(),
    ))
}

// This function is meant to detect when a shortcut is getting oddly active
// in order to help detecting phishing.
// We are aiming at *active* phishing that needs *immediate* action.
// ex: bulk phishing mails sent to 200+ email addresses in one hour.
// The SuspiciousWatcher mutex is structured as follows:
// HashMap<String, Vec<(DateTime<Utc>, String)>>
// HashMap<{SHORTCUT NAME}, Vec<({TIMESTAMP}, {IP ADDRESS})>.
// The data is kept in RAM and cleaned regularly and on program restart.
pub fn watch_visits(watcher: &web::Data<SuspiciousWatcher>, link: &LinkInfo, ip: String) {
    // locks the mutex.
    let w = watcher.lock().map_err(|e| {
        eprintln!("ERROR: watch_visits: Failed to get the mutex lock: {}", e);
    });

    // silently returns if we fail to get the lock (do NOT panic)
    if w.is_err() {
        return;
    }

    let mut w = w.unwrap();

    // get the entry corresponding to the shortcut or create a new one
    let rate_shortcut = w.entry(link.url_from.to_string()).or_insert_with(Vec::new);

    // clean up old entries
    rate_shortcut.retain(|timestamp| {
        timestamp.0
            > (Utc::now() - Duration::hours(i64::from(CONFIG.phishing.suspicious_click_timeframe)))
    });

    // check click count
    if rate_shortcut.len() >= CONFIG.phishing.suspicious_click_count {
        println!(
            "WARN: suspicious activity detected.\n\
        Link: {}\n\
        Redirects to: {}\n\
        Admin link: {}\n\
        Flag as phishing: {}\n\
        ---",
            link.url_from, link.url_to, link.adminlink, link.phishlink
        );
        // resetting activity after printing the message
        rate_shortcut.clear();
    }

    // adding the IP to list if it doesn't exist already
    if !rate_shortcut.iter().any(|val| val.1 == ip) {
        rate_shortcut.push((Utc::now(), ip));
    }
}
