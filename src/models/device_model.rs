use crate::schema::*;
use chrono::NaiveDate;

#[derive(Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone)]
#[table_name = "devices"]
#[primary_key(mac_addr)]
pub struct Device {
    mac_addr: String,
    ip_addr: String,
    hostname: String,
    vendor_class: String,
    mud_url: String,
    last_interaction: NaiveDate,
}

pub struct InsertableDevice {
    mac_addr: String,
    ip_addr: String,
    hostname: String,
    vendor_class: String,
    mud_url: String,
    last_interaction: NaiveDate,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceData {}
