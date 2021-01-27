// "captcha" was taken by the actual crate, so...
// named it "spam".

use actix_session::Session;
use actix_web::web;

use captcha::filters::{Grid, Noise, Wave};
use captcha::Captcha;
use chrono::Duration;
use chrono::{NaiveDateTime, Utc};
use rand::Rng;

use crate::database::LinkInfo;
use crate::init::*;
use crate::SuspiciousWatcher;

pub fn gen_captcha() -> Option<(String, Vec<u8>)> {
    let mut rng = rand::thread_rng();

    let mut captcha = Captcha::new();
    captcha.add_chars(CAPTCHA_LETTERS);

    for diff in 1..=CONFIG.general.captcha_difficulty {
        match diff {
            1 => captcha.apply_filter(Noise::new(0.1)),
            2 => captcha
                .apply_filter(
                    Wave::new(rng.gen_range(1..4) as f64, rng.gen_range(6..13) as f64).horizontal(),
                )
                .apply_filter(
                    Wave::new(rng.gen_range(1..4) as f64, rng.gen_range(6..13) as f64).vertical(),
                ),
            3 => captcha.apply_filter(Grid::new(rng.gen_range(15..25), rng.gen_range(15..25))),
            4 => captcha
                .apply_filter(
                    Wave::new(rng.gen_range(1..4) as f64, rng.gen_range(5..9) as f64).horizontal(),
                )
                .apply_filter(
                    Wave::new(rng.gen_range(1..4) as f64, rng.gen_range(5..9) as f64).vertical(),
                ),
            5 => captcha
                .apply_filter(
                    Wave::new(rng.gen_range(1..4) as f64, rng.gen_range(6..13) as f64).horizontal(),
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
    s.set(
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
        NaiveDateTime::parse_from_str(cookie_split.get(0)?, "%s").ok()?,
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
pub fn watch_visits(watcher: web::Data<SuspiciousWatcher>, link: LinkInfo, ip: String) {
    // locks the mutex.
    // If we can't get the lock, return early and prints an error.
    let mut w = watcher
        .lock()
        .map_err(|e| {
            eprintln!("ERROR: watch_visits: Failed to get the mutex lock: {}", e);
        })
        .unwrap();

    // get the entry corresponding to the shortcut or create a new one
    let rate_shortcut = w.entry(link.url_from.to_string()).or_insert_with(Vec::new);

    // clean up old entries
    rate_shortcut.retain(|timestamp| {
        timestamp.0
            > (Utc::now() - Duration::hours(CONFIG.phishing.suspicious_click_timeframe as i64))
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
