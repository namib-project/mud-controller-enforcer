/*
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 0.0.0
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Description {
    #[serde(rename = "mud_url")]
    pub mud_url: String,
    #[serde(rename = "mac_addr")]
    pub mac_addr: String,
}

impl Description {
    pub fn new(mud_url: String, mac_addr: String) -> Description {
        Description { mud_url, mac_addr }
    }
}
