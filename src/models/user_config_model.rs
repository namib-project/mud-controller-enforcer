// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

/// The user config has a very simple structure. A key (which is also a the primary key),
/// value (which is a string) and a referencing user id.
/// You can use it to store anything you need as Key-Values in the Database
#[derive(Debug, Serialize, Deserialize, Clone, Apiv2Schema)]
pub struct UserConfig {
    pub key: String,
    pub user_id: i64,
    pub value: String,
}
