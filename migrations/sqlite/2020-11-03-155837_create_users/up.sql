-- Your SQL goes here
CREATE TABLE users
(
    id       INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(128) NOT NULL UNIQUE,
    password VARCHAR(256) NOT NULL,
    salt     BINARY       NOT NULL
)