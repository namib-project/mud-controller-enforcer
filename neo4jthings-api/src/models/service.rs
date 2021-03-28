/*
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 0.0.0
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "product")]
    pub product: String,
    #[serde(rename = "method")]
    pub method: String,
}

impl Service {
    pub fn new(name: String, product: String, method: String) -> Service {
        Service {
            name,
            product,
            method,
        }
    }
}


