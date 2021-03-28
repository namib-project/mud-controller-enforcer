-- Add migration script here
CREATE TABLE rooms (
    room_id SERIAL NOT NULL PRIMARY KEY,
    name varchar(50) NOT NULL UNIQUE,
    color varchar(6) NOT NULL
)
