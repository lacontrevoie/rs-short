#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
#[macro_use] extern crate diesel;
#[macro_use] extern crate diesel_migrations;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate rocket_contrib;
extern crate rand;
extern crate chrono;
extern crate url;
extern crate captcha;
extern crate base64;

mod link;
mod templates;
mod form;
mod cookies;
//#[cfg(test)] mod tests;

// rocket uses
use rocket::{Rocket, State};
use rocket::http::Cookies;
use rocket::fairing::AdHoc;
use rocket::request::{Form};
use rocket::response::{Redirect};
use rocket_contrib::{templates::Template, serve::StaticFiles};

// diesel uses
use diesel::SqliteConnection;

// local uses
use link::Link;
use link::LinkInfo;
use cookies::cookie_captcha_set;
use cookies::cookie_captcha_get;
use templates::GeneralContext;
use templates::gen_captcha;
use templates::Lang;
use templates::LangHeader;
use templates::ValidLanguages;
use templates::LangChild;
use templates::tr_helper;
use templates::IPAddress;
use form::LinksForm;
use link::gen_random;

// base64 uses
use base64::{encode as base64_encode};
use base64::{encode_config as base64_encode_config};
use base64::URL_SAFE_NO_PAD;

// chrono uses
use chrono::prelude::*;
use chrono::Duration;


// constants. Please edit at your convenience
pub const INSTANCE_HOSTNAME: &str = "s.42l.fr";

pub const HOSTER_HOSTNAME: &str = "42l.fr";


// This macro from `diesel_migrations` defines an `embedded_migrations` module
// containing a function named `run`. This allows the example to be run and
// tested without any outside setup of the database.
embed_migrations!();

#[database("sqlite_database")]
pub struct DbConn(SqliteConnection);


// used to delete a link. the link name and admin key
// associated with the link are mandatory.
#[get("/<url_from>/<key>/delete")]
pub fn shortcut_admin_del(
    url_from: String,
    key: String,
    statelang: State<Lang>,
    lang_header: LangHeader,
    conn: DbConn,
    cookies: Cookies
    ) -> Template {

    let i_form_result;
    let mut form_is_valid = false;
    let mut i_captcha_data = None;

    // grabing l10n data for the page
    let loc_dict = statelang.pages["home"].clone();

    // getting user's language from request headers
    let user_lang = lang_header.0;

    // 1. check if the link exists
    if let Some(db_link_info) = Link::get_link(&url_from, &conn) {
        // 1.a the link exists.
        // 2. check if the provided key is correct
        if base64_encode_config(&db_link_info.key, URL_SAFE_NO_PAD) == key {
            // 2.a the key is correct
            // 3. try to delete the link as requested
            // unwrap: the id is None only when the link isn't in DB yet, which isn't the case.
            if Link::delete_by_id(db_link_info.id.unwrap(), &conn) {
                // 3.a delete succeded
                // display a nice success message
                form_is_valid = true;
                i_form_result = Some(loc_dict.lang["link_delete_success"][&user_lang].clone());
            }
            else {
                // 3.b delete failed. that's a problem.
                eprintln!("WARN: Delete failed for link {} (DB error)", db_link_info.url_from);
                i_form_result = Some(loc_dict.lang["error_link_delete_db_fail"][&user_lang].clone());
            }
        }
        else {
            // 2.b the key is invalid
            i_form_result = Some(loc_dict.lang["error_invalid_key"][&user_lang].clone());
        }
    }
    else {
        // 1.b the link doesn't exist
        i_form_result = Some(loc_dict.lang["error_link_not_found"][&user_lang].clone());
    }

    // generating new captcha
    // stored as a tuple (captcha_answer, captcha_png)
    if let Some(captcha_data) = gen_captcha() {
        // sets the captcha cookie
        cookie_captcha_set(&captcha_data.0, cookies);
        // converts the data to b64
        i_captcha_data = Some(base64_encode(&captcha_data.1));
    }

    Template::render(loc_dict.clone().template, &gen_default_context(
            loc_dict, user_lang, i_captcha_data, i_form_result, form_is_valid, None))

}

// the "link admin panel" route. clients are redirected to this route
// when they create a link, with created=true.
// Allows people to delete their links and check the click count.
#[get("/<url_from>/<key>?<created>")]
pub fn shortcut_admin(
    url_from: String,
    key: String,
    created: bool,
    statelang: State<Lang>,
    lang_header: LangHeader,
    conn: DbConn,
    cookies: Cookies
    ) -> Template {

    let mut form_is_valid = false;
    let mut i_form_result = None;
    let mut i_captcha_data = None;
    let mut link_info = None;

    // grabing l10n data for the page
    let loc_dict = statelang.pages["home"].clone();

    // getting user's language from request headers
    let user_lang = lang_header.0;

    // 1. check if the link exists
    if let Some(db_link_info) = Link::get_link(&url_from, &conn) {
        // 1.a the link exists.
        // 2. check if the provided key is correct
        if base64_encode_config(&db_link_info.key, URL_SAFE_NO_PAD) == key {
            // 2.a the key is correct
            // 3. display success message if the link has just been created
            if created == true {
                i_form_result = Some(loc_dict.lang["form_success"][&user_lang].clone());
                form_is_valid = true;
            }
            link_info = Some(db_link_info);
        }
        else {
            // 2.b the key is invalid
            i_form_result = Some(loc_dict.lang["error_invalid_key"][&user_lang].clone());
        }
    }
    else {
        // 1.b the link doesn't exist
        i_form_result = Some(loc_dict.lang["error_link_not_found"][&user_lang].clone());
    }

    // generating new captcha
    // stored as a tuple (captcha_answer, captcha_png)
    if let Some(captcha_data) = gen_captcha() {
        // sets the captcha cookie
        cookie_captcha_set(&captcha_data.0, cookies);
        // converts the data to b64
        i_captcha_data = Some(base64_encode(&captcha_data.1));
    }

    Template::render(loc_dict.clone().template, &gen_default_context(
            loc_dict, user_lang, i_captcha_data, i_form_result, form_is_valid, link_info))

}

// route taken by people who gets redirected.
// the click count is also incremented.
#[get("/<url_from>")]
pub fn shortcut(
    url_from: String,
    statelang: State<Lang>,
    lang_header: LangHeader,
    conn: DbConn,
    cookies: Cookies
    ) -> Result<Redirect, Template> {

    // if the link exists, redirects to it.
    if let Some(link) = Link::get_link(&url_from, &conn) {
        if Link::increment_by_id(&link, &conn) == false {
            eprintln!("WARN: Failed to increment a link. DB fail?");
        }
        Ok(Redirect::to(link.url_to))
    }
    else {
        let mut i_form_result = None;
        let mut i_captcha_data = None;
        // grabing l10n data for the page
        let loc_dict = statelang.pages["home"].clone();

        // getting user's language from request headers
        let user_lang = lang_header.0;

        if let Some(captcha_data) = gen_captcha() {
            // sets the captcha cookie
            cookie_captcha_set(&captcha_data.0, cookies);
            // converts the data to b64
            i_captcha_data = Some(base64_encode(&captcha_data.1));
            i_form_result = Some(loc_dict.lang["error_invalid_link"][&user_lang].clone());
        }

        Err(Template::render(loc_dict.clone().template, &gen_default_context(
                    loc_dict, user_lang, i_captcha_data, i_form_result, false, None)))
    }
}

// route used to create a link.
#[post("/", data = "<linkform>")]
pub fn home_post(statelang: State<Lang>,
                 lang_header: LangHeader,
                 mut cookies: Cookies,
                 conn: DbConn,
                 linkform: Form<LinksForm>,
                 addr: IPAddress
                ) -> Result<Redirect, Template> {
    // success: redirects to link admin page
    // err: displays home with error message

    // defining i_form_result's scope
    let i_form_result;
    let mut i_captcha_data = None;

    // grabing l10n data for the page
    let loc_dict = statelang.pages["home"].clone();

    // getting user's language from request headers
    let user_lang = lang_header.0;

    // 0. check if form is valid
    if let Some(linkform) = linkform.is_valid() {
        if let Some(captcha_key) = cookie_captcha_get(&mut cookies) {
            // 1. check session validity (30 minutes)
            if captcha_key.0 < (Utc::now().naive_utc() - Duration::minutes(30)) {
                // session expired
                i_form_result = Some(loc_dict.lang["error_session_expired"][&user_lang].clone());
            }
            else {
                // valid session
                // 2. check for captcha validity
                // we're cool. we don't check the case
                // (?) might change at some point
                if captcha_key.1.to_lowercase() == linkform.captcha.0.to_lowercase() {
                    // valid captcha
                    // 3. check for custom name availability
                    // generate random url_from if not specified
                    let new_url_from = match linkform.url_from.0.len() == 0 {
                        true => base64_encode_config(&gen_random(6), URL_SAFE_NO_PAD),
                        false => linkform.url_from.0,
                    };
                    // then try to get an eventual existing link from db
                    if let Some(_) = Link::get_link(&new_url_from, &conn) {
                        // error, the link already exists.
                        i_form_result = Some(loc_dict.lang["error_link_already_exists"][&user_lang].clone());
                    }
                    else {
                        // 4. the link doesn't exist, try to create it.
                        if let Some(newlink) = Link::insert(new_url_from.clone(), linkform.url_to.0, &conn) {
                            // SUCCESS ROUTE!! GOOD END
                            // redirects to the link admin page
                            return Ok(Redirect::to(uri!(
                                        shortcut_admin:
                                        newlink.url_from,
                                        base64_encode_config(&newlink.key, URL_SAFE_NO_PAD),
                                        true
                                        )));
                        }
                        else {
                            // error, db fail
                            eprintln!("WARN: Failed to insert link {} (DB error)", new_url_from);
                            i_form_result = Some(loc_dict.lang["error_db_fail"][&user_lang].clone());
                        }
                    }
                }
                else {
                    // invalid captcha!!
                    i_form_result = Some(loc_dict.lang["error_captcha_fail"][&user_lang].clone());
                    // printing captcha info to console, might be useful to analyze bots' behavior.
                    // Not printing in lowercase for a better analysis.
                    println!("INFO: [{}] failed the captcha (input: \"{}\", answer: \"{}\").",
                    addr.0, linkform.captcha.0, captcha_key.1);
                }
            }
        }
        else {
            // error : failed to parse cookie (shouldn't theorically happen)
            i_form_result = Some(loc_dict.lang["error_cookie_parse_fail"][&user_lang].clone());
        }

    }
    else {
        // error: some of the fields are invalid
        i_form_result = Some(loc_dict.lang["error_invalid_form"][&user_lang].clone());
        println!("INFO: [{}] submitted an invalid form.", addr.0);

    }

    // generating new captcha
    // stored as a tuple (captcha_answer, captcha_png)
    if let Some(captcha_data) = gen_captcha() {
        // sets the captcha cookie
        cookie_captcha_set(&captcha_data.0, cookies);
        // converts the data to b64
        i_captcha_data = Some(base64_encode(&captcha_data.1));
    }

    Err(Template::render(loc_dict.clone().template, &gen_default_context(
                loc_dict, user_lang, i_captcha_data, i_form_result, false, None)))
}

// main route.
#[get("/")]
pub fn home(statelang: State<Lang>,
            lang_header: LangHeader,
            cookies: Cookies
           ) -> Template {

    let i_form_result = None;
    let mut i_captcha_data = None;

    // grabing l10n data for the page
    let loc_dict = statelang.pages["home"].clone();

    // getting user's language from request headers
    let user_lang = lang_header.0;

    // generating new captcha
    // stored as a tuple (captcha_answer, captcha_png)
    if let Some(captcha_data) = gen_captcha() {
        // sets the captcha cookie
        cookie_captcha_set(&captcha_data.0, cookies);
        // converts the data to b64
        i_captcha_data = Some(base64_encode(&captcha_data.1));
    }

    Template::render(loc_dict.clone().template, &gen_default_context(
            loc_dict, user_lang, i_captcha_data, i_form_result, false, None))

}

// this function is used, so less code is copypasted.
fn gen_default_context(loc: LangChild,
                       lang: ValidLanguages,
                       i_captcha_data: Option<String>,
                       mut i_form_result: Option<String>,
                       mut form_is_valid: bool,
                       link_info: Option<Link>) -> GeneralContext {

    // if the captcha gen has gone wrong, overriding the error message here
    if i_captcha_data == None {
        i_form_result = Some(loc.lang["captcha_crash"][&lang].clone());
        form_is_valid = false;
    }

    GeneralContext {
        loc: loc,
        l: lang,
        captcha: i_captcha_data,
        parent: "layout",
        form_result: i_form_result,
        form_is_valid: form_is_valid,
        linkinfo: match link_info {
            Some(v) => Some(LinkInfo::create_from(v)),
            None => None,
        },
        hoster: HOSTER_HOSTNAME,
    }
}

fn rocket() -> (Rocket, Option<DbConn>) {
    let rocket = rocket::ignite()
        .manage(Lang::init())
        .attach(DbConn::fairing())
        .attach(AdHoc::on_attach("Database Migrations", |rocket| {
            let conn = DbConn::get_one(&rocket).expect("database connection");
            match embedded_migrations::run(&*conn) {
                Ok(()) => Ok(rocket),
                Err(e) => {
                    eprintln!("Failed to run database migrations: {:?}", e);
                    Err(rocket)
                },
            }
        }))
    .mount("/", routes![
           home, home_post, shortcut, shortcut_admin, shortcut_admin_del
    ])
        .mount("/assets", StaticFiles::from("assets/").rank(-10))
        .attach(Template::custom(|engines| {
            engines.handlebars.register_helper("tr", Box::new(tr_helper));
        }));

    let conn = match cfg!(test) {
        true => DbConn::get_one(&rocket),
        false => None,
    };

    (rocket, conn)
}

fn main() {
    rocket().0.launch();
}
