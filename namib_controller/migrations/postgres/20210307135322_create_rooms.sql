-- Add migration script here
CREATE TABLE rooms (
    room_id BIGSERIAL NOT NULL PRIMARY KEY,
    name varchar(50) NOT NULL UNIQUE,
    color varchar(10) NOT NULL
)
