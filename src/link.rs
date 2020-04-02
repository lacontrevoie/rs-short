// diesel uses
use diesel::{self, prelude::*};

// chrono uses
use chrono::prelude::*;

// base64 uses
use base64::{encode_config as base64_encode_config};
use base64::URL_SAFE_NO_PAD;

// RNG uses
use rand::RngCore;
use rand::rngs::OsRng;

// Links database uses
use self::schema::links;
use self::schema::links::dsl::{links as all_links};

use crate::config::CONFIG;

// The Links Table, as seen from the database
mod schema {
    table! {
        links (id) {
            id -> Nullable<Integer>,
            url_from -> Text,
            url_to -> Text,
            key -> Binary,
            time -> Timestamp,
            clicks -> Integer,
        }
    }
}


#[table_name="links"]
#[derive(Serialize, Queryable, Insertable, Debug, Clone)]
pub struct Link {
    pub id: Option<i32>,
    pub url_from: String,
    pub url_to: String,
    pub key: Vec<u8>,
    pub time: NaiveDateTime,
    pub clicks: i32,
}

#[derive(Serialize)]
pub struct LinkInfo {
    pub url_from: String,
    pub url_to: String,
    pub adminlink: String,
    pub clicks: i32,
}

// used to format data into the right URLs in link admin panel
impl LinkInfo {
    pub fn create_from(link: Link) -> Self {
        LinkInfo {
            url_from: format!("https://{}/{}", CONFIG.general.instance_hostname,
                              link.url_from),
            url_to: link.url_to,
            adminlink: format!("https://{}/{}/{}", CONFIG.general.instance_hostname,
                               link.url_from,
                               base64_encode_config(&link.key, URL_SAFE_NO_PAD)),
            clicks: link.clicks
        }
    }
}

// methods used to query the DB
impl Link {
    // gets *all links* (is this even used somewhere?)
    pub fn all(conn: &SqliteConnection) -> Vec<Link> {
        all_links.order(links::id.desc()).load::<Link>(conn).unwrap()
    }

    pub fn get_link(i_url_from: &str, conn: &SqliteConnection) -> Option<Link> {
        all_links.filter(links::url_from.eq(i_url_from)).first(conn).ok()
    }

    // click count increment
    pub fn increment_by_id(selected_link: &Link, conn: &SqliteConnection) -> bool {
        diesel::update(all_links.find(selected_link.id))
                       .set(links::clicks.eq(selected_link.clicks + 1)).execute(conn).is_ok()
    }

    // creating a new link
    pub fn insert(i_url_from: String, i_url_to: String, conn: &SqliteConnection) -> Option<Link> {
        let t = Link {
            id: None,
            url_from: i_url_from,
            url_to: i_url_to,
            time: Utc::now().naive_utc(),
            key: gen_random(24),
            clicks: 0,
            };
        match diesel::insert_into(links::table).values(&t).execute(conn).is_ok() {
            true => Some(t),
            false => None,
        }
    }

    // deleting a link with its ID
    pub fn delete_by_id(id: i32, conn: &SqliteConnection) -> bool {
        diesel::delete(all_links.find(id)).execute(conn).is_ok()
    }
}

// used to generate random strings for:
// - link admin panel (links.key field, 24 bytes)
// - short link names when none is specified (links.url_from field, 6 bytes)
pub fn gen_random(n_bytes: usize) -> Vec<u8>
{
    // Using /dev/random to generate random bytes
    let mut r = OsRng;

    let mut my_secure_bytes = vec![0u8; n_bytes];
    r.fill_bytes(&mut my_secure_bytes);
    my_secure_bytes
}

