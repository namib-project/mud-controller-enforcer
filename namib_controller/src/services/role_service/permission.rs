// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Matthias Reichmann, Hannes Masuch
// SPDX-License-Identifier: MIT OR Apache-2.0

#[allow(non_camel_case_types)]
#[derive(strum::AsRefStr, strum::ToString, Debug, strum::EnumIter, Copy, Clone)]
pub enum Permission {
    /// config/read
    #[strum(serialize = "config/read")]
    config__read,
    /// config/list
    #[strum(serialize = "config/list")]
    config__list,
    /// config/write
    #[strum(serialize = "config/write")]
    config__write,
    /// config/delete
    #[strum(serialize = "config/delete")]
    config__delete,
    /// device/list
    #[strum(serialize = "device/list")]
    device__list,
    /// device/read
    #[strum(serialize = "device/read")]
    device__read,
    /// device/write
    #[strum(serialize = "device/write")]
    device__write,
    /// device/delete
    #[strum(serialize = "device/delete")]
    device__delete,
    /// role/list
    #[strum(serialize = "role/list")]
    role__list,
    /// role/read
    #[strum(serialize = "role/read")]
    role__read,
    /// role/write
    #[strum(serialize = "role/write")]
    role__write,
    /// role/delete
    #[strum(serialize = "role/delete")]
    role__delete,
    /// role/assign
    #[strum(serialize = "role/assign")]
    role__assign,
    /// mud/list
    #[strum(serialize = "mud/list")]
    mud__list,
    /// mud/read
    #[strum(serialize = "mud/read")]
    mud__read,
    /// mud/write
    #[strum(serialize = "mud/write")]
    mud__write,
    /// mud/delete
    #[strum(serialize = "mud/delete")]
    mud__delete,
    /// mud/delete
    #[strum(serialize = "mud/create")]
    mud__create,
    /// user/management/list
    #[strum(serialize = "user/management/list")]
    user__management__list,
    /// user/management/read
    #[strum(serialize = "user/management/read")]
    user__management__read,
    /// user/management/write
    #[strum(serialize = "user/management/write")]
    user__management__write,
    /// user/management/create
    #[strum(serialize = "user/management/create")]
    user__management__create,
    /// user/management/delete
    #[strum(serialize = "user/management/delete")]
    user__management__delete,
    /// floor/list
    #[strum(serialize = "floor/list")]
    floor__list,
    /// floor/read
    #[strum(serialize = "floor/read")]
    floor__read,
    /// floor/write
    #[strum(serialize = "floor/write")]
    floor__write,
    /// floor/delete
    #[strum(serialize = "floor/delete")]
    floor__delete,
    /// floor/delete
    #[strum(serialize = "floor/create")]
    floor__create,
    /// room/list
    #[strum(serialize = "room/list")]
    room__list,
    /// room/read
    #[strum(serialize = "room/read")]
    room__read,
    /// room/write
    #[strum(serialize = "room/write")]
    room__write,
    /// room/delete
    #[strum(serialize = "room/delete")]
    room__delete,
    /// room/delete
    #[strum(serialize = "room/create")]
    room__create,
    /// enforcer/list
    #[strum(serialize = "enforcer/list")]
    enforcer__list,
    /// enforcer/read
    #[strum(serialize = "enforcer/read")]
    enforcer__read,
    /// enforcer/update
    #[strum(serialize = "enforcer/update")]
    enforcer__update,
    /// notification/list
    #[strum(serialize = "notification/list")]
    notification__list,
    /// notification/read
    #[strum(serialize = "notification/read")]
    notification__read,
    /// notification/write
    #[strum(serialize = "notification/write")]
    notification__write,
    /// notification/delete
    #[strum(serialize = "notification/delete")]
    notification__delete,
    /// anomaly/list
    #[strum(serialize = "anomaly/list")]
    anomaly__list,
    /// anomaly/read
    #[strum(serialize = "anomaly/read")]
    anomaly__read,
    /// anomaly/write
    #[strum(serialize = "anomaly/write")]
    anomaly__write,
    /// anomaly/delete
    #[strum(serialize = "anomaly/delete")]
    anomaly__delete,
    /// anomaly/create
    #[strum(serialize = "anomaly/create")]
    anomaly__create,
    /// connections/list
    #[strum(serialize = "connections/list")]
    connections__list,
}
