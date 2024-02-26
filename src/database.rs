use base64::prelude::*;
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
    pub id: i32,
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
            url_from: format!(
                "{}/{}",
                CONFIG.wait().general.instance_hostname,
                link.url_from
            ),
            url_to: link.url_to,
            adminlink: format!(
                "{}/{}/admin/{}",
                CONFIG.wait().general.instance_hostname,
                link.url_from,
                BASE64_STANDARD_NO_PAD.encode(&link.key)
            ),
            deletelink: format!(
                "{}/{}/delete/{}",
                CONFIG.wait().general.instance_hostname,
                link.url_from,
                BASE64_STANDARD_NO_PAD.encode(&link.key)
            ),
            phishlink: format!(
                "{}/{}/phishing/{}",
                CONFIG.wait().general.instance_hostname,
                link.url_from,
                CONFIG.wait().phishing.phishing_password
            ),
            clicks: link.clicks,
        }
    }
}

// methods used to query the DB
impl Link {
    // gets *all links* (is this even used somewhere?)
    pub fn all(conn: &mut DbConn) -> Vec<Link> {
        use crate::db_schema::links::dsl::{id, links};

        links.order(id.desc()).load::<Link>(conn).unwrap()
    }

    #[cfg(not(feature = "mysql"))]
    pub fn get_link_and_incr(
        i_url_from: &str,
        conn: &mut DbConn,
    ) -> Result<Option<Link>, diesel::result::Error> {
        use crate::db_schema::links::dsl::{clicks, links, url_from};

        diesel::update(links.filter(url_from.eq(i_url_from)))
            .set(clicks.eq(clicks + 1))
            .get_result(conn)
            .optional()
    }

    #[cfg(feature = "mysql")]
    pub fn get_link_and_incr(
        i_url_from: &str,
        conn: &mut DbConn,
    ) -> Result<Option<Link>, diesel::result::Error> {
        match Link::get_link(i_url_from, conn)? {
            Some(link) => match link.increment(conn) {
                Ok(_) => Ok(Some(link)),
                Err(e) => {
                    eprintln!("INFO: Failed to increment a link: {}?", e);
                    Err(e)
                }
            },
            None => Ok(None),
        }
    }

    pub fn get_link(
        i_url_from: &str,
        conn: &mut DbConn,
    ) -> Result<Option<Link>, diesel::result::Error> {
        use crate::db_schema::links::dsl::{links, url_from};

        links.filter(url_from.eq(i_url_from)).first(conn).optional()
    }

    // click count increment
    pub fn increment(&self, conn: &mut DbConn) -> Result<usize, diesel::result::Error> {
        use crate::db_schema::links::dsl::{clicks, id, links};

        diesel::update(links.filter(id.eq(self.id)))
            .set(clicks.eq(self.clicks + 1))
            .execute(conn)
    }

    // creating a new link
    #[cfg(not(feature = "mysql"))]
    pub fn insert(
        i_url_from: &str,
        i_url_to: &str,
        conn: &mut DbConn,
    ) -> Result<Link, diesel::result::Error> {
        use crate::db_schema::links::dsl::{key, time, url_from, url_to};

        diesel::insert_into(all_links)
            .values((
                url_from.eq(i_url_from),
                url_to.eq(i_url_to),
                time.eq(Utc::now().naive_utc()),
                key.eq(gen_random(24)),
            ))
            .get_result(conn)
    }

    // creating a new link
    #[cfg(feature = "mysql")]
    pub fn insert(
        i_url_from: &str,
        i_url_to: &str,
        conn: &mut DbConn,
    ) -> Result<Link, diesel::result::Error> {
        use crate::db_schema::links::dsl::*;

        diesel::insert_into(all_links)
            .values((
                url_from.eq(i_url_from),
                url_to.eq(i_url_to),
                time.eq(Utc::now().naive_utc()),
                key.eq(gen_random(24)),
            ))
            .execute(conn)?;

        match Link::get_link(i_url_from, conn)? {
            Some(l) => Ok(l),
            None => Err(diesel::result::Error::NotFound),
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
        diesel::delete(all_links.filter(links::id.eq(self.id))).execute(conn)
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
