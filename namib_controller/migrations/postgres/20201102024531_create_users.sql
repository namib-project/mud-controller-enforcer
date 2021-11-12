-- Your SQL goes here
CREATE TABLE users
(
    id       BIGSERIAL    NOT NULL PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password VARCHAR(256) NOT NULL,
    salt     BYTEA        NOT NULL
)