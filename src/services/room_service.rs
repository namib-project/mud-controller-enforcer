use crate::{
    db::DbConnection,
    error::{Error, Result},
    models::{Device, DeviceDbo},
    services::{
        config_service, config_service::ConfigKeys, firewall_configuration_service, mud_service,
        mud_service::get_mud_from_url,
    },
};
pub use futures::TryStreamExt;

use namib_shared::models::DhcpLeaseInformation;
use sqlx::Done;
use crate::models::Room;


pub async fn find_by_id(id: i64, pool: &DbConnection) -> Result<Room> {
    let room = sqlx::query_as!(Room, "select * from rooms where room_id = ?", id)
        .fetch_one(pool)
        .await?;

    Ok(room)
}

/*pub fn find_by_optional_id(id: Option<i64>, pool: &DbConnection) -> Result<Option<Room>> {
    match id {
        Some(room) => Ok(Some(find_by_id(room, pool))),
        None => Ok(None)
    }
}*/

pub fn convert_devicedbo_and_room_to_device(device: DeviceDbo, room: Room) -> Device {
    let mut device_with_room = Device::from(device);
    device_with_room.room = Some(room);
    device_with_room
}
