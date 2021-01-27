use actix_session::Session;
use actix_web::{get, http, post, web, HttpRequest, HttpResponse, Result};
use askama::Template;
use base64::encode_config as base64_encode_config;
use base64::URL_SAFE_NO_PAD;
use std::collections::HashMap;

use crate::database::*;
use crate::init::*;
use crate::routes::*;
use crate::spam::cookie_captcha_get;
use crate::spam::watch_visits;
use crate::structs::*;
use crate::templates::*;
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
) -> Result<HttpResponse> {
    // Important: the "ShortcutAdminInfo.admin_key" field
    // isn't the administration link, but the server
    // admin password defined in config.toml.
    // We just used the same struct for convenience.

    let l = get_lang(&req);

    // if the admin phishing password doesn't match, return early.
    if params.admin_key != CONFIG.phishing.phishing_password {
        println!("INFO: [{}] tried to flag a link as phishing.", get_ip(&req));
        let tpl = TplNotification::new("home", "error_bad_server_admin_key", false, &l);
        return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
    }

    // get database connection
    let conn = dbpool
        .get()
        .expect("ERROR: shortcut_admin_del: DB connection failed");

    // mark the link as phishing
    let flag_result = web::block(move || Link::flag_as_phishing(&params.url_from, &conn))
        .await
        .map_err(|e| {
            eprintln!(
                "ERROR: shortcut_admin: shortcut_admin_flag query failed: {}",
                e
            );
            let tpl = TplNotification::new("home", "error_db_fail", false, &l);
            HttpResponse::InternalServerError()
                .content_type("text/html")
                .body(gentpl_home(&l, &s, None, Some(tpl)));
        })?;

    // if flag_as_phishing returned 0, it means it affected 0 rows.
    // so link not found
    if flag_result == 0 {
        let tpl = TplNotification::new("home", "error_link_not_found", false, &l);
        web_ok(gentpl_home(&l, &s, None, Some(tpl))).await
    } else {
        let tpl = TplNotification::new("home", "link_flag_success", true, &l);
        web_ok(gentpl_home(&l, &s, None, Some(tpl))).await
    }
}

// GET: delete a link
#[get("/{url_from}/delete/{admin_key}")]
pub async fn shortcut_admin_del(
    req: HttpRequest,
    params: web::Path<ShortcutAdminInfo>,
    dbpool: web::Data<DbPool>,
    s: Session,
) -> Result<HttpResponse> {
    // INFO: Copy-paste from shortcut_admin

    let l = get_lang(&req);

    // get database connection
    let conn = dbpool
        .get()
        .expect("ERROR: shortcut_admin_del: DB connection failed");

    // getting the link from database
    let move_url_from = params.url_from.to_owned();
    let selected_link = web::block(move || Link::get_link(&move_url_from, &conn))
        .await
        .map_err(|e| {
            eprintln!("ERROR: shortcut_admin: get_link query failed: {}", e);
            let tpl = TplNotification::new("home", "error_db_fail", false, &l);
            HttpResponse::InternalServerError()
                .content_type("text/html")
                .body(gentpl_home(&l, &s, None, Some(tpl)));
        })?;

    let link = match selected_link {
        // if the administration key doesn't match, return early
        Some(v) if base64_encode_config(&v.key, URL_SAFE_NO_PAD) != params.admin_key => {
            let tpl = TplNotification::new("home", "error_invalid_key", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
        }
        Some(v) => v,
        // if the link doesn't exist, return early
        None => {
            let tpl = TplNotification::new("home", "error_link_not_found", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
        }
    };

    // if the link is a phishing link, prevent deletion. Early return
    if link.phishing > 0 {
        let tpl = TplNotification::new("home", "error_not_deleting_phishing", false, &l);
        return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
    }

    // get a new database connection
    // because the other one has been consumed by another thread...
    let conn = dbpool
        .get()
        .expect("ERROR: shortcut_admin_del: 2th DB connection failed");

    // deleting the link
    web::block(move || link.delete(&conn)).await.map_err(|e| {
        eprintln!("ERROR: shortcut_admin: delete query failed: {}", e);
        let tpl = TplNotification::new("home", "error_link_delete_db_fail", false, &l);
        HttpResponse::InternalServerError()
            .content_type("text/html")
            .body(gentpl_home(&l, &s, None, Some(tpl)));
    })?;

    // displaying success message
    let tpl = TplNotification::new("home", "link_delete_success", true, &l);
    web_ok(gentpl_home(&l, &s, None, Some(tpl))).await
}

// GET: link administration page, fallback compatibility
// for older links
#[get("/{url_from}/{admin_key}")]
pub async fn shortcut_admin_fallback(params: web::Path<ShortcutAdminInfo>) -> Result<HttpResponse> {
    web_redir(&format!(
        "{}/{}/admin/{}",
        &CONFIG.general.instance_hostname, params.url_from, params.admin_key
    ))
    .await
}

// GET: link administration page
#[get("/{url_from}/admin/{admin_key}")]
pub async fn shortcut_admin(
    req: HttpRequest,
    params: web::Path<ShortcutAdminInfo>,
    dbpool: web::Data<DbPool>,
    s: Session,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse> {
    let l = get_lang(&req);

    // get database connection
    let conn = dbpool
        .get()
        .expect("ERROR: shortcut_admin: DB connection failed");

    // getting the link from database
    let move_url_from = params.url_from.to_owned();
    let selected_link = web::block(move || Link::get_link(&move_url_from, &conn))
        .await
        .map_err(|e| {
            eprintln!("ERROR: shortcut_admin: get_link query failed: {}", e);
            let tpl = TplNotification::new("home", "error_db_fail", false, &l);
            HttpResponse::InternalServerError()
                .content_type("text/html")
                .body(gentpl_home(&l, &s, None, Some(tpl)));
        })?;

    let linkinfo = match selected_link {
        // if the administration key doesn't match, return early
        Some(v) if base64_encode_config(&v.key, URL_SAFE_NO_PAD) != params.admin_key => {
            let tpl = TplNotification::new("home", "error_invalid_key", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
        }
        // if the link is marked as phishing, the administration page
        // can't be accessed anymore
        Some(v) if v.phishing >= 1 => {
            let tpl = TplNotification::new("home", "error_not_managing_phishing", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
        }
        // generate linkinfo for templating purposes
        Some(v) => LinkInfo::create_from(v),
        // if the link doesn't exist, return early
        None => {
            let tpl = TplNotification::new("home", "error_link_not_found", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
        }
    };

    // proceeding to page display

    // if created=true, display a green notification
    if query.get("created").is_some() {
        let tpl = TplNotification::new("home", "form_success", true, &l);
        web_ok(gentpl_home(&l, &s, Some(linkinfo), Some(tpl))).await
    } else {
        web_ok(gentpl_home(&l, &s, Some(linkinfo), None)).await
    }
}

// POST: Submit a new link
#[post("/")]
pub async fn post_link(
    req: HttpRequest,
    s: Session,
    dbpool: web::Data<DbPool>,
    form: web::Form<NewLink>,
) -> Result<HttpResponse> {
    let l = get_lang(&req);

    // Get the cookie, returning early if the cookie
    // can't be retrieved or parsed.
    let cookie = match cookie_captcha_get(&s) {
        Some(v) => v,
        None => {
            eprintln!("WARN: [{}]: failed to parse cookie", get_ip(&req));
            let tpl = TplNotification::new("home", "error_cookie_parse_fail", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
        }
    };

    // checking the form
    // if it returns Err(template), early return
    if let Some(tpl_error) = form.validate(&l, &req, cookie).err() {
        return web_ok(gentpl_home(&l, &s, None, Some(tpl_error))).await;
    }

    // prevent shortening loop
    if form.url_to.contains(
        &CONFIG
            .general
            .instance_hostname
            .replace("http://", "")
            .replace("https://", ""),
    ) {
        eprintln!(
            "INFO: [{}] tried to create a shortening loop.",
            get_ip(&req)
        );
        let tpl = TplNotification::new("home", "error_selflink_forbidden", false, &l);
        return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
    }

    // check for blacklists
    if blacklist_check(&form.url_from, &URL_FROM_BL, true)
        || blacklist_check(&form.url_to, &URL_TO_BL, false)
    {
        println!(
            "WARN: [{}] banned (url blacklist).\n\
            Shortcut: {}\n\
            Link: {}\n\
            ---",
            get_ip(&req),
            &form.url_from,
            &form.url_to
        );
        return HttpResponse::Forbidden()
            .body(&LANG.pages["home"].map["error_blacklisted_link"][&l])
            .await;
    }

    let mut is_allowed = false;
    // check protocols whitelist
    for r in ALLOWED_PROTOCOLS {
        if form.url_to.starts_with(r) {
            is_allowed = true;
        }
    }

    // if the protocol is forbidden, throws a friendly error
    if !is_allowed {
        eprintln!(
            "INFO: [{}] submitted an URL with an unsupported protocol: {}",
            get_ip(&req), &form.url_to,
        );
        let tpl = TplNotification::new("home", "error_unsupported_protocol", false, &l);
        return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
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
        .expect("ERROR: post_link: DB connection failed");

    // query the database for an existing link
    // and creates a link if it doesn't exist
    let new_link =
        web::block(move || Link::insert_if_not_exists(&new_url_from, &form.url_to, &conn))
            .await
            .map_err(|e| {
                eprintln!("ERROR: post_link: insert_if_not_exists query failed: {}", e);
                let tpl = TplNotification::new("home", "error_db_fail", false, &l);
                HttpResponse::InternalServerError()
                    .content_type("text/html")
                    .body(gentpl_home(&l, &s, None, Some(tpl)));
            })?;

    // if the link already exists, early return.
    let new_link = match new_link {
        Some(v) => v,
        None => {
            println!(
                "INFO: [{}] tried to shorten an already shortened link.",
                get_ip(&req)
            );
            let tpl = TplNotification::new("home", "error_link_already_exists", false, &l);
            return web_ok(gentpl_home(&l, &s, None, Some(tpl))).await;
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
    web_redir(&format!("{}{}", &linkinfo.adminlink, "?created=true")).await
}

// get routed through a shortcut
#[get("/{url_from}")]
pub async fn shortcut(
    req: HttpRequest,
    params: web::Path<ShortcutInfo>,
    dbpool: web::Data<DbPool>,
    suspicious_watch: web::Data<SuspiciousWatcher>,
    s: Session,
) -> Result<HttpResponse> {
    let l = get_lang(&req);

    // get database connection
    let conn = dbpool.get().expect("ERROR: shortcut: DB connection failed");

    // gets the link from database
    // and increments the click count
    let selected_link = web::block(move || Link::get_link_and_incr(&params.url_from, &conn))
        .await
        .map_err(|e| {
            eprintln!("ERROR: shortcut: get_link query failed: {}", e);
            let tpl = TplNotification::new("home", "error_db_fail", false, &l);
            HttpResponse::InternalServerError()
                .content_type("text/html")
                .body(gentpl_home(&l, &s, None, Some(tpl)));
        })?;

    match selected_link {
        // if the link does not exist, renders home template
        // with a 404 Not Found http status code
        None => {
            let tpl = TplNotification::new("home", "error_invalid_link", false, &l);
            HttpResponse::NotFound()
                .content_type("text/html")
                .body(gentpl_home(&l, &s, None, Some(tpl)))
                .await
        }
        // if the link exists but phishing=1, renders home
        // with a 410 Gone http status code
        Some(link) if link.phishing > 0 => {
            // render the phishing template
            // (only used once)
            HttpResponse::Gone()
                .content_type("text/html")
                .body(
                    PhishingTemplate {
                        loc: &LANG.pages["phishing"].map,
                        l: &l,
                        config: &CONFIG.general,
                    }
                    .render()
                    .expect("Failed to render phishing template"),
                )
                .await
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
            web_redir(&link.url_to).await
        }
    }
}

#[get("/")]
pub async fn index(req: HttpRequest, s: Session) -> Result<HttpResponse> {
    web_ok(gentpl_home(&get_lang(&req), &s, None, None)).await
}

pub fn web_ok(content: String) -> HttpResponse {
    HttpResponse::Ok().content_type("text/html").body(content)
}

fn web_redir(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .header(http::header::LOCATION, location)
        .finish()
}
