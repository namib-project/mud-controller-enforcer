// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use paperclip::actix::Apiv2Schema;

#[derive(Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct StatusDto {
    pub setup_required: bool,
    pub signup_allowed: bool,
    pub version: &'static str,
    pub secure_name: Option<String>,
}
