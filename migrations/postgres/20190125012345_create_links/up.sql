CREATE TABLE links (
    id serial4 PRIMARY KEY UNIQUE NOT NULL,
    url_from VARCHAR NOT NULL,
    url_to VARCHAR NOT NULL,
    key bytea NOT NULL,
    time TIMESTAMP NOT NULL,
    clicks INTEGER NOT NULL DEFAULT 0
);
