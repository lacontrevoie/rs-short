use actix_session::Session;
use actix_web::{get, http, post, web, HttpRequest, HttpResponse, Result};
use base64::encode_config as base64_encode_config;
use base64::URL_SAFE_NO_PAD;
use std::collections::HashMap;

use crate::database::{Link, LinkInfo};
use crate::error_handlers::{crash, ShortCircuit, ErrorKind};
use crate::init::{ALLOWED_PROTOCOLS, CONFIG, URL_FROM_BL, URL_TO_BL, URL_TO_SOFTBL};
use crate::routes::{ShortcutAdminInfo, ShortcutInfo};
use crate::spam::watch_visits;
use crate::spam::{cookie_captcha_get, cookie_captcha_set};
use crate::structs::NewLink;
use crate::templates::{
    blacklist_check, gen_random, gentpl_home, get_ip, get_lang, TplNotification,
};
use crate::DbPool;
use crate::SuspiciousWatcher;

// GET: flag a link as phishing
// Can only be used by the server admin
#[get("/{url_from}/phishing/{admin_key}")]
pub async fn shortcut_admin_flag(
    req: HttpRequest,
    params: web::Path<ShortcutAdminInfo>,
    dbpool: web::Data<DbPool>,
    s: Session,
) -> Result<HttpResponse, ShortCircuit> {
    // Important: the "ShortcutAdminInfo.admin_key" field
    // isn't the administration link, but the server
    // admin password defined in config.toml.
    // We just used the same struct for convenience.

    let captcha = cookie_captcha_set(&s);

    // if the admin phishing password doesn't match, return early.
    if params.admin_key != CONFIG.phishing.phishing_password {
        return Err(crash(ErrorKind::WarnBadServerAdminKey, "tried to flag a link as phishing".into(), get_ip(&req), get_lang(&req), captcha));
    }

    // get database connection
    let conn = dbpool
        .get()
        .map_err(|e| {
            crash(ErrorKind::CritDbPool, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // mark the link as phishing
    let flag_result = web::block(move || Link::flag_as_phishing(&params.url_from, &conn))
        .await
        .map_err(|e| {
            crash(ErrorKind::CritDbFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?
        .map_err(|e| {
            crash(ErrorKind::CritAwaitFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // if flag_as_phishing returned 0, it means it affected 0 rows.
    // so link not found
    if flag_result == 0 {
        return Err(crash(ErrorKind::InfoLinkNotFound, "tried to flag a non-existing phishing link".into(), get_ip(&req), get_lang(&req), captcha));
    } else {
        let tpl = TplNotification::new("home", "link_flag_success", true, &get_lang(&req));
        Ok(HttpResponse::Ok().body(gentpl_home(&get_lang(&req), captcha.as_deref(), None, Some(&tpl))))
    }
}

// GET: delete a link
#[get("/{url_from}/delete/{admin_key}")]
pub async fn shortcut_admin_del(
    req: HttpRequest,
    params: web::Path<ShortcutAdminInfo>,
    dbpool: web::Data<DbPool>,
    s: Session,
) -> Result<HttpResponse, ShortCircuit> {
    // INFO: Copy-paste from shortcut_admin

    let captcha = cookie_captcha_set(&s);

    // get database connection
    let conn = dbpool
        .get()
        .map_err(|e| {
            crash(ErrorKind::CritDbPool, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // getting the link from database
    let move_url_from = params.url_from.to_owned();
    let selected_link = web::block(move || Link::get_link(&move_url_from, &conn))
        .await
        .map_err(|e| {
            crash(ErrorKind::CritDbFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?
        .map_err(|e| {
            crash(ErrorKind::CritAwaitFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    let link = match selected_link {
        // if the administration key doesn't match, return early
        Some(v) if base64_encode_config(&v.key, URL_SAFE_NO_PAD) != params.admin_key => {
            return Err(crash(ErrorKind::NoticeInvalidKey, "the provided link admin key is incorrect".into(), get_ip(&req), get_lang(&req), captcha.clone()));
        }
        Some(v) => v,
        // if the link doesn't exist, return early
        None => {
            return Err(crash(ErrorKind::InfoLinkNotFound, "the link to delete doesn’t exist".into(), get_ip(&req), get_lang(&req), captcha.clone()));
        }
    };

    // if the link is a phishing link, prevent deletion. Early return
    if link.phishing > 0 {
        return Err(crash(ErrorKind::NoticeNotDeletingPhishing, "tried to delete a phishing link".into(), get_ip(&req), get_lang(&req), captcha.clone()));
    }

    // get a new database connection
    // because the other one has been consumed by another thread...
    let conn = dbpool
        .get()
        .map_err(|e| {
            crash(ErrorKind::CritDbPool, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // deleting the link
    web::block(move || link.delete(&conn))
        .await
        .map_err(|e| {
            crash(ErrorKind::CritLinkDeleteDbFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?
        .map_err(|e| {
            crash(ErrorKind::CritAwaitFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // displaying success message
    let tpl = TplNotification::new("home", "link_delete_success", true, &get_lang(&req));
    Ok(HttpResponse::Ok().body(gentpl_home(&get_lang(&req), captcha.as_deref(), None, Some(&tpl))))
}

// GET: link administration page, fallback compatibility
// for older links
#[get("/{url_from}/{admin_key}")]
pub async fn shortcut_admin_fallback(params: web::Path<ShortcutAdminInfo>) -> Result<HttpResponse, ShortCircuit> {
    Ok(web_redir(&format!(
        "{}/{}/admin/{}",
        &CONFIG.general.instance_hostname, params.url_from, params.admin_key
    )))
}

// GET: link administration page
#[get("/{url_from}/admin/{admin_key}")]
pub async fn shortcut_admin(
    req: HttpRequest,
    params: web::Path<ShortcutAdminInfo>,
    dbpool: web::Data<DbPool>,
    s: Session,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, ShortCircuit> {
    let captcha = cookie_captcha_set(&s);

    // get database connection
    let conn = dbpool
        .get()
        .map_err(|e| {
            crash(ErrorKind::CritDbPool, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // getting the link from database
    let move_url_from = params.url_from.to_owned();
    let selected_link = web::block(move || Link::get_link(&move_url_from, &conn))
        .await
        .map_err(|e| {
            crash(ErrorKind::CritDbFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?
        .map_err(|e| {
            crash(ErrorKind::CritAwaitFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    let linkinfo = match selected_link {
        // if the administration key doesn't match, return early
        Some(v) if base64_encode_config(&v.key, URL_SAFE_NO_PAD) != params.admin_key => {
            return Err(crash(ErrorKind::NoticeInvalidKey, "the provided link admin key is invalid".into(), get_ip(&req), get_lang(&req), captcha.clone()));
        }
        // if the link is marked as phishing, the administration page
        // can't be accessed anymore
        Some(v) if v.phishing >= 1 => {
            return Err(crash(ErrorKind::NoticeNotManagingPhishing, "tried to manage a phishing link".into(), get_ip(&req), get_lang(&req), captcha.clone()))
        }
        // generate linkinfo for templating purposes
        Some(v) => LinkInfo::create_from(v),
        // if the link doesn't exist, return early
        None => {
            return Err(crash(ErrorKind::InfoLinkNotFound, "the link to manage doesn’t exist".into(), get_ip(&req), get_lang(&req), captcha.clone()))
        }
    };

    // proceeding to page display

    // if created=true, display a green notification
    if query.get("created").is_some() {
        let tpl = TplNotification::new("home", "form_success", true, &get_lang(&req));
        Ok(HttpResponse::Ok().body(gentpl_home(
            &get_lang(&req),
            captcha.as_deref(),
            Some(&linkinfo),
            Some(&tpl),
        )))
    } else {
        Ok(HttpResponse::Ok().body(gentpl_home(&get_lang(&req), captcha.as_deref(), Some(&linkinfo), None)))
    }
}

// POST: Submit a new link
// captcha function is not called first, else it would override session cookie
#[post("/")]
pub async fn post_link(
    req: HttpRequest,
    s: Session,
    dbpool: web::Data<DbPool>,
    form: web::Form<NewLink>,
) -> Result<HttpResponse, ShortCircuit> {
    // Get the cookie, returning early if the cookie
    // can't be retrieved or parsed.
    let cookie = match cookie_captcha_get(&s) {
        Some(v) => v,
        None => {
            let captcha = cookie_captcha_set(&s);
            return Err(crash(ErrorKind::NoticeCookieParseFail, "failed to parse cookie".into(), get_ip(&req), get_lang(&req), captcha.clone()))
        }
    };

    // checking the form
    // if it returns Err(template), early return
    if let Some(tpl_error) = form.validate(cookie.clone()).err() {
        let captcha = cookie_captcha_set(&s);
        if tpl_error == ErrorKind::WarnCaptchaFail {
            return Err(crash(tpl_error, format!("captcha failed: {} | {}", form.captcha.to_lowercase(), cookie.1.to_lowercase()), get_ip(&req), get_lang(&req), captcha.clone()));
        } else {
            return Err(crash(tpl_error, "form validation failed".into(), get_ip(&req), get_lang(&req), captcha.clone()));
        }
    }

    // prevent shortening loop
    if form.url_to.contains(
        &CONFIG
            .general
            .instance_hostname
            .replace("http://", "")
            .replace("https://", ""),
    ) {
        let captcha = cookie_captcha_set(&s);
        return Err(crash(ErrorKind::InfoSelflinkForbidden, format!("tried to create a shortening loop with link {}", form.url_to), get_ip(&req), get_lang(&req), captcha.clone()))
    }

    // check for soft blacklists
    // Do not ban, just display a friendly error
    if blacklist_check(&form.url_to, &URL_TO_SOFTBL, false) {
        let captcha = cookie_captcha_set(&s);
        return Err(crash(ErrorKind::WarnShortlinkForbidden, format!("matched an URL in the soft blocklist. URL: {} | Shortcut name: {}", form.url_to, &form.url_from), get_ip(&req), get_lang(&req), captcha.clone()))
    }

    // check for blacklists
    if blacklist_check(&form.url_from, &URL_FROM_BL, true)
        || blacklist_check(&form.url_to, &URL_TO_BL, false)
    {
        let captcha = cookie_captcha_set(&s);
        return Err(crash(ErrorKind::WarnBlocklistedLink, format!("matched an URL in the hard blocklist. URL: {} | Shortcut name: {}", form.url_to, &form.url_from), get_ip(&req), get_lang(&req), captcha.clone()))
    }

    let mut is_allowed = false;
    // check protocols whitelist
    for r in ALLOWED_PROTOCOLS {
        if form.url_to.trim().starts_with(r) {
            is_allowed = true;
        }
    }

    // if the protocol is forbidden, throws a friendly error
    if !is_allowed {
        let captcha = cookie_captcha_set(&s);
        return Err(crash(ErrorKind::NoticeUnsupportedProtocol, format!("submitted an URL with an unsupported protocol. URL: {}", form.url_to), get_ip(&req), get_lang(&req), captcha.clone()))
    }

    // if the user hasn't chosen a shortcut name, decide for them.
    let new_url_from = if form.url_from.is_empty() {
        base64_encode_config(&gen_random(6), URL_SAFE_NO_PAD)
    } else {
        form.url_from.clone()
    };

    // get database connection
    let conn = dbpool
        .get()
        .map_err(|e| {
            let captcha = cookie_captcha_set(&s);
            crash(ErrorKind::CritDbPool, e.to_string(), get_ip(&req), get_lang(&req), captcha)
        })?;

    let url_from_copy = form.url_from.clone();
    // query the database for an existing link
    // and creates a link if it doesn't exist
    let new_link =
        web::block(move || Link::insert_if_not_exists(&new_url_from, form.url_to.trim(), &conn))
            .await
            .map_err(|e| {
                let captcha = cookie_captcha_set(&s);
                crash(ErrorKind::CritDbFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
            })?
            .map_err(|e| {
                let captcha = cookie_captcha_set(&s);
                crash(ErrorKind::CritAwaitFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
            })?;

    // if the link already exists, early return.
    let new_link = match new_link {
        Some(v) => v,
        None => {
            let captcha = cookie_captcha_set(&s);
            return Err(crash(ErrorKind::NoticeLinkAlreadyExists, format!("tried to create a shortcut which already exists: {}", &url_from_copy.trim()), get_ip(&req), get_lang(&req), captcha.clone()));
        }
    };

    // get the new link in a readable, template-ready format
    let linkinfo = LinkInfo::create_from(new_link);

    // if phishing verbose is enabled, display link creation info in console
    if CONFIG.phishing.verbose_console {
        println!(
            "NOTE: New link created: {}\n\
            Redirects to: {}\n\
            Admin link: {}\n\
            Flag as phishing: {}\n\
            ---",
            linkinfo.url_from, linkinfo.url_to, linkinfo.adminlink, linkinfo.phishlink
        );
    }

    // redirects to the link admin page
    Ok(web_redir(&format!(
        "{}{}",
        &linkinfo.adminlink, "?created=true"
    )))
}

// get routed through a shortcut
#[get("/{url_from}")]
pub async fn shortcut(
    req: HttpRequest,
    params: web::Path<ShortcutInfo>,
    dbpool: web::Data<DbPool>,
    suspicious_watch: web::Data<SuspiciousWatcher>,
    s: Session,
) -> Result<HttpResponse, ShortCircuit> {
    let captcha = cookie_captcha_set(&s);

    // get database connection
    let conn = dbpool.get()
        .map_err(|e| {
            crash(ErrorKind::CritDbPool, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // gets the link from database
    // and increments the click count
    let thread_url_from = params.url_from.clone();
    let selected_link = web::block(move || Link::get_link_and_incr(&thread_url_from, &conn))
        .await
        .map_err(|e| {
            crash(ErrorKind::CritAwaitFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
        })?;

    // hard fail (500 error) if query + failover query isn't enough
    let selected_link = selected_link.map_err(|e| {
        eprintln!("ERROR: shortcut: get_link query failed: {}", e);
        crash(ErrorKind::CritDbFail, e.to_string(), get_ip(&req), get_lang(&req), captcha.clone())
    })?;

    match selected_link {
        // if the link does not exist, renders home template
        // with a 404 Not Found http status code
        None => {
            Err(crash(ErrorKind::InfoInvalidLink, "link not found in DB".into(), get_ip(&req), get_lang(&req), captcha.clone()))
        }
        // if the link exists but phishing=1, renders home
        // with a 410 Gone http status code
        Some(link) if link.phishing > 0 => {
            // render the phishing template
            // (only used once)
            Err(crash(ErrorKind::InfoPhishingLinkReached, format!("phishing link reached. Shortcut name: {}", link.url_from), get_ip(&req), get_lang(&req), captcha.clone()))
        }
        // else, redirects with a 303 See Other.
        // if verbose_suspicious is enabled, play with the Mutex.
        Some(link) => {
            if CONFIG.phishing.verbose_suspicious {
                watch_visits(
                    suspicious_watch,
                    LinkInfo::create_from(link.clone()),
                    get_ip(&req),
                );
            }

            Ok(web_redir(&link.url_to))
        }
    }
}

#[get("/")]
pub async fn index(req: HttpRequest, s: Session) -> Result<HttpResponse, ShortCircuit> {
    let captcha = cookie_captcha_set(&s);
    Ok(HttpResponse::Ok().body(gentpl_home(&get_lang(&req), captcha.as_deref(), None, None)))
}

fn web_redir(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, location))
        .finish()
}
