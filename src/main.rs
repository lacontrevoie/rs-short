#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate diesel;

extern crate diesel_migrations;

extern crate base64;
extern crate captcha;

mod database;
mod db_schema;
mod error_handlers;
mod handlers;
mod init;
mod routes;
mod spam;
mod structs;
mod templates;

use actix_files as fs;
use actix_session::storage::CookieSessionStore;
use actix_session::config::CookieContentSecurity;
use actix_session::SessionMiddleware;
use actix_web::cookie::SameSite;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};

use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

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

#[cfg(feature = "postgres")]
type DbConn = PgConnection;
#[cfg(feature = "postgres")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgres");
#[cfg(feature = "postgres")]
type DB = diesel::pg::Pg;

#[cfg(feature = "sqlite")]
type DbConn = SqliteConnection;
#[cfg(feature = "sqlite")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
#[cfg(feature = "sqlite")]
type DB = diesel::sqlite::Sqlite;

#[cfg(feature = "mysql")]
type DbConn = MysqlConnection;
#[cfg(feature = "mysql")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");
#[cfg(feature = "mysql")]
type DB = diesel::mysql::Mysql;

type DbPool = r2d2::Pool<ConnectionManager<DbConn>>;

// see the watch_visits function for more details on the watcher
type SuspiciousWatcher = Mutex<HashMap<String, Vec<(DateTime<Utc>, String)>>>;

fn run_migrations(connection: &mut impl MigrationHarness<DB>) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {

    // This will run the necessary migrations.
    //
    // See the documentation for `MigrationHarness` for
    // all available methods.
    connection.run_pending_migrations(MIGRATIONS)?;

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("rs-short, starting.");
    println!("initializing config.");
    init::init_config();

    println!("Opening database {}", CONFIG.get().unwrap().general.database_path);
    // connecting the sqlite database
    let manager = ConnectionManager::<DbConn>::new(&CONFIG.get().unwrap().general.database_path);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    let mut conn = pool.get().expect("ERROR: main: DB connection failed");

    println!("Running migrations");
    run_migrations(&mut conn).expect("Failed to run migrations.");

    // for verbose_suspicious option
    let suspicious_watch = Data::new(Mutex::new(HashMap::<
        String,
        Vec<(DateTime<Utc>, String)>,
    >::new()));

    // check configuration version
    // and panic if it doesn't match CONFIG_VERSION
    CONFIG.get().unwrap().check_version();

    // starting the http server
    println!("Server listening at {}", CONFIG.get().unwrap().general.listening_address);
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(suspicious_watch.clone())
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    get_cookie_key(&CONFIG.get().unwrap().general.cookie_key),
                )
                .cookie_content_security(CookieContentSecurity::Signed)
                .cookie_secure(true)
                .cookie_name("rs-short-captcha".to_string())
                .cookie_same_site(SameSite::Strict)
                .cookie_http_only(true)
                .build(),
            )
            .service(fs::Files::new("/assets", "./assets"))
            .service(index)
            .service(shortcut)
            .service(shortcut_admin)
            .service(shortcut_admin_flag)
            .service(shortcut_admin_del)
            .service(shortcut_admin_fallback)
            .service(post_link)
            .default_service(web::to(default_handler))
    })
    .bind(&CONFIG.get().unwrap().general.listening_address)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL_FROM: &str = "git_de_42l";
    const URL_TO: &str = "https://git.42l.fr/";

    fn create_db() -> r2d2::Pool<ConnectionManager<SqliteConnection>> {
        let manager = ConnectionManager::<DbConn>::new(":memory:");
        r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to create pool.")
    }

    #[test]
    fn create_link() {
        let pool = create_db();
        let mut conn = pool.get().expect("Failed to create sql connection.");
        run_migrations(&mut conn).expect("Failed to run migrations.");

        let res = database::Link::insert(URL_FROM, URL_TO, &mut conn).expect("Could not insert Link in database.");

        assert_eq!(res.url_from, URL_FROM);
        assert_eq!(res.url_to, URL_TO)
    }

    #[test]
    fn get_link_exists() {
        let pool = create_db();
        let mut conn = pool.get().expect("Failed to create sql connection.");
        run_migrations(&mut conn).expect("Failed to run migrations.");

        database::Link::insert(URL_FROM, URL_TO, &mut conn).expect("Could not insert Link in database.");

        let res = database::Link::get_link(URL_FROM, &mut conn).expect("Could not retrieve Link in database.");

        assert!(res.is_some());
        assert_eq!(res.unwrap().url_to, URL_TO);
    }

    #[test]
    fn get_link_not_exists() {
        let pool = create_db();
        let mut conn = pool.get().expect("Failed to create sql connection.");
        run_migrations(&mut conn).expect("Failed to run migrations.");

        database::Link::insert(URL_FROM, URL_TO, &mut conn).expect("Could not insert Link in database.");

        let res = database::Link::get_link("wrong_url", &mut conn).expect("Could not retrieve Link in database.");

        assert!(res.is_none());
    }

    #[test]
    fn get_link_and_incr_not_exists() {
        let pool = create_db();
        let mut conn = pool.get().expect("Failed to create sql connection.");
        run_migrations(&mut conn).expect("Failed to run migrations.");

        database::Link::insert(URL_FROM, URL_TO, &mut conn).expect("Could not insert Link in database.");

        let res = database::Link::get_link_and_incr("wrong_url", &mut conn).expect("Could not retrieve Link in database.");

        assert!(res.is_none());
    }

    #[test]
    fn get_link_view_count() {
        let pool = create_db();
        let mut conn = pool.get().expect("Failed to create sql connection.");
        run_migrations(&mut conn).expect("Failed to run migrations.");

        database::Link::insert(URL_FROM, URL_TO, &mut conn).expect("Could not insert Link in database.");

        let res = database::Link::get_link(URL_FROM, &mut conn).expect("Could not retrieve Link in database.");

        assert!(res.is_some());
        let link_orig = res.unwrap();
        assert_eq!(link_orig.url_to, URL_TO);
        assert_eq!(link_orig.clicks, 0);

        let res = database::Link::get_link_and_incr(URL_FROM, &mut conn).expect("Could not retrieve Link in database.");
        assert!(res.is_some());
        let link = res.unwrap();
        assert_eq!(link.url_to, URL_TO);
        assert_eq!(link.clicks, 1);

        let res = database::Link::get_link(URL_FROM, &mut conn).expect("Could not retrieve Link in database.");

        assert!(res.is_some());
        let link_orig = res.unwrap();
        assert_eq!(link_orig.url_to, URL_TO);
        assert_eq!(link_orig.clicks, 1);
    }
}