// Copyright 2020-2021, Benjamin Ludewig, Florian Bonetti, Jeffrey Munstermann, Luca Nittscher, Hugo Damer, Michael Bach
// SPDX-License-Identifier: MIT OR Apache-2.0

use paperclip::actix::Apiv2Schema;
use serde::Deserialize;

#[derive(Deserialize, Apiv2Schema)]
pub struct ConfigQueryDto {
    #[serde(default, deserialize_with = "comma_seperated")]
    pub keys: Vec<String>,
}

fn comma_seperated<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?
        .split_whitespace()
        .collect::<String>();

    if raw.is_empty() {
        return Ok(vec![]);
    }

    let strings = raw.split(',');
    Ok(strings.map(std::string::ToString::to_string).collect())
}
