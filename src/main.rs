#![feature(try_blocks)]

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
mod routes;
mod handlers;
mod init;
mod spam;
mod structs;
mod templates;

use actix_files as fs;
use actix_session::CookieSession;
use actix_web::{App, web, HttpServer};

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

use chrono::Utc;
use chrono::DateTime;

use crate::handlers::*;
use crate::init::*;

use base64::decode as base64_decode;

use std::collections::HashMap;
use std::sync::Mutex;

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

// see the watch_visits function for more details on the watcher
type SuspiciousWatcher = Mutex<HashMap<String, Vec<(DateTime<Utc>, String)>>>;

embed_migrations!();

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    println!("rs-short, starting.");
    
    std::env::set_var("RUST_LOG", "actix_web=debug");
        env_logger::init();

    println!("Opening database {}", CONFIG.general.database_path);
    // connecting the sqlite database
    let manager = ConnectionManager::<SqliteConnection>::new(&CONFIG.general.database_path);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    let conn = pool
        .get()
        .expect("ERROR: main: DB connection failed");
    
    println!("Running migrations");
    embedded_migrations::run(&*conn).expect("Failed to run database migrations");

    // for verbose_suspicious option
    let suspicious_watch = web::Data::new(
            Mutex::new(HashMap::<String, Vec<(DateTime<Utc>, String)>>::new()));

    // starting the http server
    println!("Server listening at {}", CONFIG.general.listening_address);
    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .app_data(suspicious_watch.clone())
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
    })
    .bind(&CONFIG.general.listening_address)?
        .run()
        .await
}
