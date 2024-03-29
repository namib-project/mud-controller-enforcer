/*
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 0.0.0
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PatchedMud {
    #[serde(rename = "mud_version", skip_serializing_if = "Option::is_none")]
    pub mud_version: Option<i32>,
    #[serde(rename = "mud_url", skip_serializing_if = "Option::is_none")]
    pub mud_url: Option<String>,
    #[serde(rename = "mud_signature", skip_serializing_if = "Option::is_none")]
    pub mud_signature: Option<String>,
    #[serde(rename = "cache_validity", skip_serializing_if = "Option::is_none")]
    pub cache_validity: Option<i32>,
    #[serde(rename = "systeminfo", skip_serializing_if = "Option::is_none")]
    pub systeminfo: Option<String>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "firmware_rev", skip_serializing_if = "Option::is_none")]
    pub firmware_rev: Option<String>,
    #[serde(rename = "software_rev", skip_serializing_if = "Option::is_none")]
    pub software_rev: Option<String>,
    #[serde(rename = "documentation", skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
}

impl PatchedMud {
    #[allow(clippy::new_without_default)]
    pub fn new() -> PatchedMud {
        PatchedMud {
            mud_version: None,
            mud_url: None,
            mud_signature: None,
            cache_validity: None,
            systeminfo: None,
            name: None,
            firmware_rev: None,
            software_rev: None,
            documentation: None,
        }
    }
}
