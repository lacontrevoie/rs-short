use base64::encode_config as base64_encode_config;
use base64::URL_SAFE_NO_PAD;
use chrono::{NaiveDateTime, Utc};

use diesel::{self, prelude::*};

use crate::db_schema::links;
use crate::db_schema::links::dsl::links as all_links;

use crate::init::CONFIG;
use crate::templates::gen_random;
use crate::DbConn;

#[derive(Serialize, Queryable, Insertable, Debug, Clone)]
#[diesel(table_name = links)]
pub struct Link {
    pub id: Option<i32>,
    pub url_from: String,
    pub url_to: String,
    pub key: Vec<u8>,
    pub time: NaiveDateTime,
    pub clicks: i32,
    pub phishing: i32,
}

#[derive(Debug)]
pub struct LinkInfo {
    pub url_from: String,
    pub url_to: String,
    pub adminlink: String,
    pub deletelink: String,
    pub phishlink: String,
    pub clicks: i32,
}

// used to format data into the right URLs in link admin panel
impl LinkInfo {
    pub fn create_from(link: Link) -> Self {
        LinkInfo {
            url_from: format!("{}/{}", CONFIG.general.instance_hostname, link.url_from),
            url_to: link.url_to,
            adminlink: format!(
                "{}/{}/admin/{}",
                CONFIG.general.instance_hostname,
                link.url_from,
                base64_encode_config(&link.key, URL_SAFE_NO_PAD)
            ),
            deletelink: format!(
                "{}/{}/delete/{}",
                CONFIG.general.instance_hostname,
                link.url_from,
                base64_encode_config(&link.key, URL_SAFE_NO_PAD)
            ),
            phishlink: format!(
                "{}/{}/phishing/{}",
                CONFIG.general.instance_hostname, link.url_from, CONFIG.phishing.phishing_password
            ),
            clicks: link.clicks,
        }
    }
}

// methods used to query the DB
impl Link {
    // gets *all links* (is this even used somewhere?)
    pub fn all(conn: &mut DbConn) -> Vec<Link> {
        all_links
            .order(links::id.desc())
            .load::<Link>(conn)
            .unwrap()
    }

    pub fn get_link_and_incr(
        i_url_from: &str,
        conn: &mut DbConn,
    ) -> Result<Option<Link>, diesel::result::Error> {
        // if the link exists, increments the click count
        if let Some(l) = Link::get_link(i_url_from, conn)? {
            // actually, if the link is a phishing link, don't increment
            if l.phishing == 0 {
                // if we fail to increment, just return the link
                // and display an error message
                if l.increment(conn).is_err() {
                    eprintln!("INFO: Failed to increment a link: database is locked?");
                }
            }
            Ok(Some(l))
        } else {
            Ok(None)
        }
    }

    pub fn get_link(
        i_url_from: &str,
        conn: &mut DbConn,
    ) -> Result<Option<Link>, diesel::result::Error> {
        all_links
            .filter(links::url_from.eq(i_url_from))
            .first(conn)
            .optional()
    }

    // click count increment
    pub fn increment(&self, conn: &mut DbConn) -> Result<usize, diesel::result::Error> {
        diesel::update(all_links.filter(links::id.is(self.id)))
            .set(links::clicks.eq(self.clicks + 1))
            .execute(conn)
    }

    // creating a new link
    pub fn insert(
        i_url_from: &str,
        i_url_to: &str,
        conn: &mut DbConn,
    ) -> Result<Link, diesel::result::Error> {
        let t = Link {
            id: None,
            url_from: i_url_from.to_string(),
            url_to: i_url_to.to_string(),
            time: Utc::now().naive_utc(),
            key: gen_random(24),
            clicks: 0,
            phishing: 0,
        };
        match diesel::insert_into(links::table).values(&t).execute(conn) {
            Ok(_) => Ok(t),
            Err(e) => Err(e),
        }
    }

    // returns Ok(None) if the link already exists
    // else, returns Ok(Link)
    pub fn insert_if_not_exists(
        i_url_from: &str,
        i_url_to: &str,
        conn: &mut DbConn,
    ) -> Result<Option<Link>, diesel::result::Error> {
        if Link::get_link(i_url_from, conn)?.is_some() {
            Ok(None)
        } else {
            Ok(Some(Link::insert(i_url_from, i_url_to, conn)?))
        }
    }

    // deleting a link with its ID
    pub fn delete(&self, conn: &mut DbConn) -> Result<usize, diesel::result::Error> {
        diesel::delete(all_links.filter(links::id.is(self.id))).execute(conn)
    }

    pub fn flag_as_phishing(
        i_url_from: &str,
        conn: &mut DbConn,
    ) -> Result<usize, diesel::result::Error> {
        diesel::update(all_links)
            .filter(links::url_from.eq(i_url_from))
            .set(links::phishing.eq(1))
            .execute(conn)
    }
}
