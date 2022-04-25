use crate::cache::{check_cached_links, save_cached_links};
use chrono::Utc;

use crate::database::Link;
use crate::init::CONFIG;

use actix_web::web;
use std::sync::Mutex;

#[test]
fn test_save_cached_links_always_caches() {
    let cache = web::Data::new(Mutex::new(Vec::<Link>::new()));

    for link_id in 0..(CONFIG.general.max_cache_size * 2) {
        let l = Link {
            id: Some(link_id as i32),
            url_from: format!("{:?}", link_id),
            url_to: "foo".into(),
            key: Vec::new(),
            time: Utc::now().naive_utc(),
            clicks: 0,
            phishing: 0,
        };
        assert!(
            check_cached_links(&l.url_from, &cache).is_none(),
            "Link not yet cached #{}",
            link_id
        );

        save_cached_links(l.clone(), &cache);

        let cached_link = check_cached_links(&l.url_from, &cache);
        assert!(cached_link.is_some(), "link cached #{}", l.id.unwrap());

        let cached_link = cached_link.unwrap();
        assert_eq!((cached_link.id, &cached_link.url_from), (l.id, &l.url_from));
    }
    //println!("New cache: after MAX_CACHE_SIZE * 2 iterations: {:#?}", cache);
}
