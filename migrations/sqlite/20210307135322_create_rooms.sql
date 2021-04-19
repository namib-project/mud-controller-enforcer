-- Add migration script here
CREATE TABLE rooms (
   room_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
   name varchar(50) NOT NULL UNIQUE,
   color varchar(10) NOT NULL
)
