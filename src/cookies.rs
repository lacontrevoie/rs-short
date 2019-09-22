// Rocket uses
use rocket::http::{Cookie, Cookies};

// chrono uses
use chrono::{NaiveDateTime, Utc};

pub const COOKIE_CAPTCHA: &str = "captcha_key";

// shall be called at the end of every single GET or POST request.
pub fn cookie_captcha_set(captcha_answer: &str, mut cookies: Cookies) {
    cookies.add_private(Cookie::new(COOKIE_CAPTCHA,
                                    format!("{}|{}",
                                            Utc::now().naive_utc().format("%s"),
                                            captcha_answer)));
}

pub fn cookie_captcha_get(cookies: &mut Cookies) -> Option<(NaiveDateTime, String)> {
    match cookies.get_private(COOKIE_CAPTCHA) {
        Some(c) => {
            let splitted_cookie: Vec<&str> = c.value().split('|').collect();
            if splitted_cookie.len() == 2 {
                match NaiveDateTime::parse_from_str(splitted_cookie[0], "%s") {
                    Ok(d) => {
                        // returning a tuple (DateTime, captcha_answer)
                        Some((d, String::from(splitted_cookie[1])))
                    },
                    Err(e) => {
                        // shouldn't happen unless the user is able to forge their private cookies
                        // or there was a problem during cookie writing
                        eprintln!("WARN: cookie_captcha_get: failed to parse DateTime: {:?}", e);
                        None
                    }
                }
            }
            else {
                // shouldn't happen either (see above)
                eprintln!("WARN: cookie_captcha_get: cookie is not formatted correctly");
                None
            }
        }
        None => {
            eprintln!("WARN: The user has no cookie, or failed to read cookie.");
            None
        }
    }
}
