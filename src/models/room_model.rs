use palette::Srgb;

#[derive(Debug, Clone)]
pub struct RoomDbo {
    pub id: i64,
    pub name: String,
    pub color: u32,
}

pub struct Room {
    pub id: i64,
    pub name: String,
    pub color: Srgb,
}
