table! {
    devices (id) {
        id -> Integer,
        ip_addr -> Text,
        mac_addr -> Nullable<Text>,
        hostname -> Text,
        vendor_class -> Text,
        mud_url -> Nullable<Text>,
        last_interaction -> Timestamp,
    }
}

table! {
    mud_data (url) {
        url -> Text,
        data -> Text,
        created_at -> Timestamp,
        expiration -> Timestamp,
    }
}

table! {
    roles (id) {
        id -> Integer,
        name -> Text,
        permissions -> Text,
    }
}

table! {
    users (id) {
        id -> Integer,
        username -> Text,
        password -> Text,
        salt -> Binary,
    }
}

table! {
    users_roles (id) {
        id -> Integer,
        user_id -> Integer,
        role_id -> Integer,
    }
}

joinable!(devices -> mud_data (mud_url));
joinable!(users_roles -> roles (role_id));
joinable!(users_roles -> users (user_id));

allow_tables_to_appear_in_same_query!(
    devices,
    mud_data,
    roles,
    users,
    users_roles,
);
