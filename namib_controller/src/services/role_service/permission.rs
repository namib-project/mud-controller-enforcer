// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
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
}
