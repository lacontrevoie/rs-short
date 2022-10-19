use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::{get, http, post, web, HttpRequest, HttpResponse, Result};
use base64::encode_config as base64_encode_config;
use base64::URL_SAFE_NO_PAD;
use std::collections::HashMap;

use crate::database::{Link, LinkInfo};
use crate::error_handlers::{crash, pass, throw, ErrorKind, ShortCircuit};
use crate::init::{CONFIG, POLICY};
use crate::routes::{ShortcutAdminInfo, ShortcutInfo};
use crate::spam::watch_visits;
use crate::spam::{cookie_captcha_get, cookie_captcha_set};
use crate::structs::NewLink;
use crate::templates::{gen_random, gentpl_home, get_ip, get_lang, TplNotification};
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

    // if the admin phishing password doesn't match, return early.
    if params.admin_key != CONFIG.wait().phishing.phishing_password {
        return Err(crash(
            throw(
                ErrorKind::WarnBadServerAdminKey,
                "tried to flag a link as phishing".into(),
            ),
            pass(&req, &s),
        ));
    }

    // get database connection
    let mut conn = dbpool
        .get()
        .map_err(|e| crash(throw(ErrorKind::CritDbPool, e.to_string()), pass(&req, &s)))?;

    // mark the link as phishing
    let flag_result = web::block(move || Link::flag_as_phishing(&params.url_from, &mut conn))
        .await
        .map_err(|e| crash(throw(ErrorKind::CritDbFail, e.to_string()), pass(&req, &s)))?
        .map_err(|e| {
            crash(
                throw(ErrorKind::CritAwaitFail, e.to_string()),
                pass(&req, &s),
            )
        })?;

    // if flag_as_phishing returned 0, it means it affected 0 rows.
    // so link not found
    if flag_result == 0 {
        Err(crash(
            throw(
                ErrorKind::InfoLinkNotFound,
                "tried to flag a non-existing phishing link".into(),
            ),
            pass(&req, &s),
        ))
    } else {
        let tpl = TplNotification::new("home", "link_flag_success", true, &get_lang(&req));
        Ok(HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(gentpl_home(
                &get_lang(&req),
                cookie_captcha_set(&s).as_deref(),
                None,
                Some(&tpl),
            )))
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

    // get database connection
    let mut conn = dbpool
        .get()
        .map_err(|e| crash(throw(ErrorKind::CritDbPool, e.to_string()), pass(&req, &s)))?;

    // getting the link from database
    let move_url_from = params.url_from.clone();
    let selected_link = web::block(move || Link::get_link(&move_url_from, &mut conn))
        .await
        .map_err(|e| crash(throw(ErrorKind::CritDbFail, e.to_string()), pass(&req, &s)))?
        .map_err(|e| {
            crash(
                throw(ErrorKind::CritAwaitFail, e.to_string()),
                pass(&req, &s),
            )
        })?;

    let link = match selected_link {
        // if the administration key doesn't match, return early
        Some(v) if base64_encode_config(&v.key, URL_SAFE_NO_PAD) != params.admin_key => {
            return Err(crash(
                throw(
                    ErrorKind::NoticeInvalidKey,
                    "the provided link admin key is incorrect".into(),
                ),
                pass(&req, &s),
            ));
        }
        Some(v) => v,
        // if the link doesn't exist, return early
        None => {
            return Err(crash(
                throw(
                    ErrorKind::InfoLinkNotFound,
                    "the link to delete doesn’t exist".into(),
                ),
                pass(&req, &s),
            ));
        }
    };

    // if the link is a phishing link, prevent deletion. Early return
    if link.phishing > 0 {
        return Err(crash(
            throw(
                ErrorKind::NoticeNotDeletingPhishing,
                "tried to delete a phishing link".into(),
            ),
            pass(&req, &s),
        ));
    }

    // get a new database connection
    // because the other one has been consumed by another thread...
    let mut conn = dbpool
        .get()
        .map_err(|e| crash(throw(ErrorKind::CritDbPool, e.to_string()), pass(&req, &s)))?;

    // deleting the link
    web::block(move || link.delete(&mut conn))
        .await
        .map_err(|e| {
            crash(
                throw(ErrorKind::CritLinkDeleteDbFail, e.to_string()),
                pass(&req, &s),
            )
        })?
        .map_err(|e| {
            crash(
                throw(ErrorKind::CritAwaitFail, e.to_string()),
                pass(&req, &s),
            )
        })?;

    // displaying success message
    let tpl = TplNotification::new("home", "link_delete_success", true, &get_lang(&req));
    Ok(HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(gentpl_home(
            &get_lang(&req),
            cookie_captcha_set(&s).as_deref(),
            None,
            Some(&tpl),
        )))
}

// GET: link administration page, fallback compatibility
// for older links
#[get("/{url_from}/{admin_key}")]
pub async fn shortcut_admin_fallback(
    params: web::Path<ShortcutAdminInfo>,
) -> Result<HttpResponse, ShortCircuit> {
    Ok(web_redir(&format!(
        "{}/{}/admin/{}",
        &CONFIG.wait().general.instance_hostname,
        params.url_from,
        params.admin_key
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
    // get database connection
    let mut conn = dbpool
        .get()
        .map_err(|e| crash(throw(ErrorKind::CritDbPool, e.to_string()), pass(&req, &s)))?;

    // getting the link from database
    let move_url_from = params.url_from.clone();
    let selected_link = web::block(move || Link::get_link(&move_url_from, &mut conn))
        .await
        .map_err(|e| crash(throw(ErrorKind::CritDbFail, e.to_string()), pass(&req, &s)))?
        .map_err(|e| {
            crash(
                throw(ErrorKind::CritAwaitFail, e.to_string()),
                pass(&req, &s),
            )
        })?;

    let linkinfo = match selected_link {
        // if the administration key doesn't match, return early
        Some(v) if base64_encode_config(&v.key, URL_SAFE_NO_PAD) != params.admin_key => {
            return Err(crash(
                throw(
                    ErrorKind::NoticeInvalidKey,
                    "the provided link admin key is invalid".into(),
                ),
                pass(&req, &s),
            ));
        }
        // if the link is marked as phishing, the administration page
        // can't be accessed anymore
        Some(v) if v.phishing >= 1 => {
            return Err(crash(
                throw(
                    ErrorKind::NoticeNotManagingPhishing,
                    "tried to manage a phishing link".into(),
                ),
                pass(&req, &s),
            ));
        }
        // generate linkinfo for templating purposes
        Some(v) => LinkInfo::create_from(v),
        // if the link doesn't exist, return early
        None => {
            return Err(crash(
                throw(
                    ErrorKind::InfoLinkNotFound,
                    "the link to manage doesn’t exist".into(),
                ),
                pass(&req, &s),
            ));
        }
    };

    // proceeding to page display

    // if created=true, display a green notification
    if query.get("created").is_some() {
        let tpl = TplNotification::new("home", "form_success", true, &get_lang(&req));
        Ok(HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(gentpl_home(
                &get_lang(&req),
                cookie_captcha_set(&s).as_deref(),
                Some(&linkinfo),
                Some(&tpl),
            )))
    } else {
        Ok(HttpResponse::Ok()
            .content_type(ContentType::html())
            .body(gentpl_home(
                &get_lang(&req),
                cookie_captcha_set(&s).as_deref(),
                Some(&linkinfo),
                None,
            )))
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
            return Err(crash(
                throw(
                    ErrorKind::NoticeCookieParseFail,
                    "failed to parse cookie".into(),
                ),
                pass(&req, &s),
            ));
        }
    };

    // checking the form

    // if it returns Err(ErrorKind), early return
    let uri = form
        .validate(&cookie.clone())
        .map_err(|e| crash(e, pass(&req, &s)))?;

    // prevent shortening loop. Host string has already been checked
    if uri.host().unwrap()
        == CONFIG
            .wait()
            .general
            .instance_hostname
            .replace("http://", "")
            .replace("https://", "")
    {
        return Err(crash(
            throw(
                ErrorKind::InfoSelflinkForbidden,
                format!(
                    "tried to create a shortening loop with link {}",
                    form.url_to
                ),
            ),
            pass(&req, &s),
        ));
    }

    POLICY
        .wait()
        .blocklist_check_from(&form.url_from)
        .map_err(|e| crash(e, pass(&req, &s)))?;
    POLICY
        .wait()
        .blocklist_check_to(&uri)
        .map_err(|e| crash(e, pass(&req, &s)))?;

    // if the user hasn't chosen a shortcut name, decide for them.
    let new_url_from = if form.url_from.is_empty() {
        base64_encode_config(&gen_random(6), URL_SAFE_NO_PAD)
    } else {
        form.url_from.clone()
    };

    // get database connection
    let mut conn = dbpool
        .get()
        .map_err(|e| crash(throw(ErrorKind::CritDbPool, e.to_string()), pass(&req, &s)))?;

    let url_from_copy = form.url_from.clone();
    // query the database for an existing link
    // and creates a link if it doesn't exist
    let new_link = web::block(move || {
        Link::insert_if_not_exists(&new_url_from, form.url_to.trim(), &mut conn)
    })
    .await
    .map_err(|e| crash(throw(ErrorKind::CritDbFail, e.to_string()), pass(&req, &s)))?
    .map_err(|e| {
        crash(
            throw(ErrorKind::CritAwaitFail, e.to_string()),
            pass(&req, &s),
        )
    })?;

    // if the link already exists, early return.
    let new_link = match new_link {
        Some(v) => v,
        None => {
            return Err(crash(
                throw(
                    ErrorKind::NoticeLinkAlreadyExists,
                    format!(
                        "tried to create a shortcut which already exists: {}",
                        &url_from_copy.trim()
                    ),
                ),
                pass(&req, &s),
            ));
        }
    };

    // get the new link in a readable, template-ready format
    let linkinfo = LinkInfo::create_from(new_link);

    // if phishing verbose is enabled, display link creation info in console
    if !POLICY
        .wait()
        .is_allowlisted(&linkinfo.url_from, &linkinfo.url_to)
        && CONFIG.wait().phishing.verbose_console
    {
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
    // get database connection
    let mut conn = dbpool
        .get()
        .map_err(|e| crash(throw(ErrorKind::CritDbPool, e.to_string()), pass(&req, &s)))?;

    // gets the link from database
    // and increments the click count
    let thread_url_from = params.url_from.clone();
    let selected_link = web::block(move || Link::get_link_and_incr(&thread_url_from, &mut conn))
        .await
        .map_err(|e| {
            crash(
                throw(ErrorKind::CritAwaitFail, e.to_string()),
                pass(&req, &s),
            )
        })?;

    // hard fail (500 error) if query + failover query isn't enough
    let selected_link = selected_link.map_err(|e| {
        eprintln!("ERROR: shortcut: get_link query failed: {}", e);
        crash(throw(ErrorKind::CritDbFail, e.to_string()), pass(&req, &s))
    })?;

    match selected_link {
        // if the link does not exist, renders home template
        // with a 404 Not Found http status code
        None => Err(crash(
            throw(ErrorKind::InfoInvalidLink, "link not found in DB".into()),
            pass(&req, &s),
        )),
        // if the link exists but phishing=1, renders home
        // with a 410 Gone http status code
        Some(link) if link.phishing > 0 => {
            // render the phishing template
            // (only used once)
            Err(crash(
                throw(
                    ErrorKind::InfoPhishingLinkReached,
                    format!("phishing link reached. shortcut name: {}", link.url_from),
                ),
                pass(&req, &s),
            ))
        }
        // else, redirects with a 303 See Other.
        // if verbose_suspicious is enabled, play with the Mutex.
        // Do NOT count visits if link is allowlisted.
        Some(link) => {
            if !POLICY.wait().is_allowlisted(&link.url_from, &link.url_to)
                && CONFIG.wait().phishing.verbose_suspicious
            {
                watch_visits(
                    &suspicious_watch,
                    &LinkInfo::create_from(link.clone()),
                    get_ip(&req),
                );
            }

            Ok(web_redir(&link.url_to))
        }
    }
}

#[get("/")]
pub async fn index(req: HttpRequest, s: Session) -> Result<HttpResponse, ShortCircuit> {
    Ok(HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(gentpl_home(
            &get_lang(&req),
            cookie_captcha_set(&s).as_deref(),
            None,
            None,
        )))
}

fn web_redir(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, location))
        .finish()
}
