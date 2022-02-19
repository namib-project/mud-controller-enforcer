// Copyright 2020-2022, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach, Matthias Reichmann
// SPDX-License-Identifier: MIT OR Apache-2.0

use paperclip::actix::Apiv2Schema;

#[derive(Debug, Clone, Serialize, Deserialize, Apiv2Schema, PartialEq)]
pub struct Room {
    pub room_id: i64,
    pub floor_id: i64,
    pub number: String,
    pub guest: Option<String>,
}
