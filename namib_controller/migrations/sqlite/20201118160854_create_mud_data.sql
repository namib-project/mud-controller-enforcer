-- Your SQL goes here
create table mud_data
(
    url        text not null primary key,
    data       text not null,
    created_at datetime not null,
    expiration datetime not null
)
