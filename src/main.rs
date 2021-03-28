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
mod handlers;
mod error_handlers;
mod init;
mod routes;
mod spam;
mod cache;
mod structs;
mod templates;
#[cfg(test)]
mod tests;

use actix_files as fs;
use actix_session::CookieSession;
use actix_web::{web, App, HttpServer, guard, HttpResponse};

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

use chrono::DateTime;
use chrono::Utc;

use crate::handlers::*;
use crate::error_handlers::*;
use crate::init::*;
use crate::database::Link;

use base64::decode as base64_decode;

use std::collections::HashMap;
use std::sync::Mutex;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

// see the watch_visits function for more details on the watcher
type SuspiciousWatcher = Mutex<HashMap<String, Vec<(DateTime<Utc>, String)>>>;

// Failsafe preventing 500 Internal Server Errors because of db locks
type LinkCache = Mutex<Vec<Link>>;

embed_migrations!();

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    println!("rs-short, starting.");

    println!("Opening database {}", CONFIG.general.database_path);
    // connecting the sqlite database
    let manager = ConnectionManager::<SqliteConnection>::new(&CONFIG.general.database_path);
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

    let link_cache = web::Data::new(Mutex::new(Vec::<Link>::new()));

    // check configuration version
    // and panic if it doesn't match CONFIG_VERSION
    CONFIG.check_version();

    // starting the http server
    println!("Server listening at {}", CONFIG.general.listening_address);
    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .data(link_cache.clone())
            .app_data(suspicious_watch.clone())
            .app_data(link_cache.clone())
            .wrap(
                CookieSession::private(
                    &base64_decode(&CONFIG.general.cookie_key)
                    .expect("Couldn't read the specified cookie_key"),
                )
                .name("rs-short-captcha")
                .secure(true),
            )
            .service(fs::Files::new("/assets", "./assets"))
            .service(index)
            .service(shortcut)
            .service(shortcut_admin)
            .service(shortcut_admin_flag)
            .service(shortcut_admin_del)
            .service(shortcut_admin_fallback)
            .service(post_link)
            .default_service(
                // 404 for GET request
                web::resource("")
                .route(web::get().to(error_404))
                // all requests that are not `GET`
                .route(
                    web::route()
                    .guard(guard::Not(guard::Get()))
                    .to(HttpResponse::MethodNotAllowed),
                ),
            )
    })
    .bind(&CONFIG.general.listening_address)?
        .run()
        .await
}

