-- Your SQL goes here
CREATE TABLE roles
(
    id          BIGSERIAL    NOT NULL PRIMARY KEY,
    name        VARCHAR(128) NOT NULL UNIQUE,
    permissions TEXT         NOT NULL DEFAULT ''
);

CREATE TABLE users_roles
(
    id      BIGSERIAL NOT NULL PRIMARY KEY,
    user_id BIGINT    NOT NULL REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE,
    role_id BIGINT    NOT NULL REFERENCES roles (id) ON UPDATE CASCADE
);