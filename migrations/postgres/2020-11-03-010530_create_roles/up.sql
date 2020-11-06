-- Your SQL goes here
CREATE TABLE roles
(
    id          SERIAL       NOT NULL PRIMARY KEY,
    name        VARCHAR(128) NOT NULL UNIQUE,
    permissions TEXT         NOT NULL DEFAULT '{}'
);

CREATE TABLE users_roles
(
    id      SERIAL  NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles (id) ON UPDATE CASCADE
);