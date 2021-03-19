-- Add migration script here
CREATE TABLE rooms (
   room_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
   name varchar(50) NOT NULL UNIQUE,
   color varchar(6) NOT NULL CHECK(color >= 0 AND color < 16777216)--Exmple: RGB #FFFFFF = 16 777 215
)





