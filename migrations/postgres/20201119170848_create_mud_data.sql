-- Your SQL goes here
create table mud_data
(
    url        text not null primary key,
    data       text not null,
    created_at timestamp with time zone not null,
    expiration timestamp with time zone not null
)
