// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::field_reassign_with_default)]

use paperclip::actix::Apiv2Schema;

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct MgmCreateUserDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
    pub roles_ids: Vec<i64>,
}

#[derive(Validate, Serialize, Deserialize, Apiv2Schema)]
pub struct MgmUpdateUserBasicDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    pub password: Option<String>,
    pub change_next_login: bool,
}
