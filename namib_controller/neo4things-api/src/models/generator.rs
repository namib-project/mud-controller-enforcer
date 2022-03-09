/*
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 0.0.0
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Generator {
    #[serde(rename = "file")]
    pub file: String,
    #[serde(rename = "gateway_mac")]
    pub gateway_mac: String,
    #[serde(rename = "gateway_ipv4")]
    pub gateway_ipv4: String,
    #[serde(rename = "gateway_ipv6")]
    pub gateway_ipv6: String,
    #[serde(rename = "device_name")]
    pub device_name: String,
    #[serde(rename = "device_mac")]
    pub device_mac: String,
}

impl Generator {
    pub fn new(
        file: String,
        gateway_mac: String,
        gateway_ipv4: String,
        gateway_ipv6: String,
        device_name: String,
        device_mac: String,
    ) -> Generator {
        Generator {
            file,
            gateway_mac,
            gateway_ipv4,
            gateway_ipv6,
            device_name,
            device_mac,
        }
    }
}
