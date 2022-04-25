#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;

extern crate base64;
extern crate captcha;
extern crate url;

mod database;
mod db_schema;
mod error_handlers;
mod handlers;
mod init;
mod routes;
mod spam;
mod structs;
mod templates;
#[cfg(test)]
mod tests;

use actix_files as fs;
use actix_session::storage::CookieSessionStore;
use actix_session::CookieContentSecurity;
use actix_session::SessionMiddleware;
use actix_web::cookie::SameSite;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

use chrono::DateTime;
use chrono::Utc;

use crate::error_handlers::default_handler;
use crate::handlers::{
    index, post_link, shortcut, shortcut_admin, shortcut_admin_del, shortcut_admin_fallback,
    shortcut_admin_flag,
};
use crate::init::{get_cookie_key, CONFIG};

use std::collections::HashMap;
use std::sync::Mutex;

// default to sqlite
#[cfg(feature = "default")]
type DbConn = SqliteConnection;
#[cfg(feature = "default")]
embed_migrations!("migrations/sqlite");

#[cfg(feature = "postgres")]
type DbConn = PgConnection;
#[cfg(feature = "postgres")]
embed_migrations!("migrations/postgres");

#[cfg(feature = "sqlite")]
type DbConn = SqliteConnection;
#[cfg(feature = "sqlite")]
embed_migrations!("migrations/sqlite");

#[cfg(feature = "mysql")]
type DbConn = MysqlConnection;
#[cfg(feature = "mysql")]
embed_migrations!("migrations/mysql");

type DbPool = r2d2::Pool<ConnectionManager<DbConn>>;

// see the watch_visits function for more details on the watcher
type SuspiciousWatcher = Mutex<HashMap<String, Vec<(DateTime<Utc>, String)>>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("rs-short, starting.");

    println!("Opening database {}", CONFIG.general.database_path);
    // connecting the sqlite database
    let manager = ConnectionManager::<DbConn>::new(&CONFIG.general.database_path);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    let conn = pool.get().expect("ERROR: main: DB connection failed");

    println!("Running migrations");
    embedded_migrations::run(&*conn).expect("Failed to run database migrations");

    // for verbose_suspicious option
    let suspicious_watch = web::Data::new(Mutex::new(HashMap::<
        String,
        Vec<(DateTime<Utc>, String)>,
    >::new()));

    // check configuration version
    // and panic if it doesn't match CONFIG_VERSION
    CONFIG.check_version();

    // starting the http server
    println!("Server listening at {}", CONFIG.general.listening_address);
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(suspicious_watch.clone())
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    get_cookie_key(&CONFIG.general.cookie_key),
                )
                .cookie_content_security(CookieContentSecurity::Signed)
                .cookie_secure(true)
                .cookie_name("rs-short-captcha".to_string())
                .cookie_same_site(SameSite::Strict)
                .cookie_http_only(true)
                .build(),
            )
            /*.wrap(
                CookieSession::private(
                    &base64_decode(&CONFIG.general.cookie_key)
                    .expect("Couldn't read the specified cookie_key"),
                )
                .name("rs-short-captcha")
                .secure(true),
            )*/
            .service(fs::Files::new("/assets", "./assets"))
            .service(index)
            .service(shortcut)
            .service(shortcut_admin)
            .service(shortcut_admin_flag)
            .service(shortcut_admin_del)
            .service(shortcut_admin_fallback)
            .service(post_link)
            .default_service(web::to(default_handler))
        /*.default_service(
            // 404 for GET request
            web::resource("")
            .route(web::get().to(error_404))
            .route(
                web::route()
                .guard(guard::Not(guard::Get()))
                .to(HttpResponse::MethodNotAllowed),
            ),
        )*/
    })
    .bind(&CONFIG.general.listening_address)?
    .run()
    .await
}
