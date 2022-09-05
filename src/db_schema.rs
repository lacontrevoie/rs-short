table! {
    links (id) {
        id -> Integer,
        url_from -> Text,
        url_to -> Text,
        key -> Binary,
        time -> Timestamp,
        clicks -> Integer,
        phishing -> Integer,
    }
}
