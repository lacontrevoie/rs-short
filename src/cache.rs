use actix_web::web;

use crate::database::Link;
use crate::LinkCache;
use crate::init::CONFIG;

pub fn check_cached_links(url_from: &str, link_cache: &web::Data<LinkCache>) -> Option<Link> {

    // if we can't get the mutex lock, return None
    let cache = link_cache
        .lock()
        .map_err(|e| {
            eprintln!("ERROR: check_cached_links: Failed to get the mutex lock: {}", e);
        }).ok()?;

    cache.iter().find(|link| link.url_from == url_from).cloned()
}

pub fn save_cached_links(new_link: Link, link_cache: &web::Data<LinkCache>) {
    // if we can't get the mutex lock, return None
    let cache = link_cache
        .lock()
        .map_err(|e| {
            eprintln!("ERROR: check_cached_links: Failed to get the mutex lock: {}", e);
        });
    
    // silently returns if we fail to get the lock
    if cache.is_err() {
        return ;
    }
    
    let mut cache = cache.unwrap();

    // add the item if it doesn't exist yet 
    if cache.iter().find(|link| link.id == new_link.id).is_none() {
        cache.push(new_link);
    }

    // remove elements if the cache gets too big
    if cache.len() > CONFIG.general.max_cache_size as usize
    && cache.len() > (CONFIG.general.max_cache_size - CONFIG.general.max_cache_size / 10) as usize {
        let to_remove = (CONFIG.general.max_cache_size / 10) as usize;
        cache.drain(to_remove..);
    }
}
