CREATE TABLE flow_scopes (
    id           INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
    name         VARCHAR(50)  NOT NULL UNIQUE,
    --level        VARCHAR(50)  NOT NULL,
    level        INTEGER      NOT NULL, -- CHECK (level IN (0, 1)),
    ttl          INTEGER      NOT NULL CHECK (ttl >= 0),
    starts_at    DATETIME     NOT NULL CHECK (starts_at >= 0)
);

CREATE TABLE flow_scopes_devices (
    id             INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_scope_id  INTEGER NOT NULL REFERENCES flow_scopes (id) ON UPDATE CASCADE ON DELETE CASCADE,
    device_id      INTEGER NOT NULL REFERENCES devices (id) ON UPDATE CASCADE
);
