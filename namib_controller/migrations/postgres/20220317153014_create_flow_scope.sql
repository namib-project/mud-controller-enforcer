CREATE TABLE flow_scopes (
    id           BIGSERIAL      NOT NULL PRIMARY KEY,
    name         VARCHAR(50)    NOT NULL UNIQUE,
    level        BIGINT         NOT NULL CHECK (level >= 0 AND level<= 1),
    ttl          BIGINT         NOT NULL CHECK (ttl >= 0),
    starts_at    TIMESTAMP      NOT NULL
);

CREATE TABLE flow_scopes_devices (
    id             BIGSERIAL    NOT NULL PRIMARY KEY,
    flow_scope_id  BIGINT       NOT NULL REFERENCES flow_scopes (id) ON UPDATE CASCADE ON DELETE CASCADE,
    device_id      BIGINT       NOT NULL REFERENCES devices (id) ON UPDATE CASCADE
);