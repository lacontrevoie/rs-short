table! {
    links (id) {
        id -> Nullable<Integer>,
        url_from -> Text,
        url_to -> Text,
        key -> Binary,
        time -> Timestamp,
        clicks -> Integer,
        phishing -> Integer,
    }
}
