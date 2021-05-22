// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use paperclip::actix::Apiv2Schema;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct RoleAssignDto {
    /// Id of the role
    pub role_id: i64,
    /// User id
    pub user_id: i64,
}
