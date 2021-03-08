use strum_macros::EnumIter;

#[allow(non_camel_case_types)]
#[derive(strum_macros::ToString, Debug, EnumIter)]
pub enum Permission {
    /// config/read
    #[strum(serialize = "config/read")]
    config__read,
    /// config/list
    #[strum(serialize = "config/list")]
    config__list,
    /// config/write
    #[strum(serialize = "config/write")]
    config__write,
    /// config/delete
    #[strum(serialize = "config/delete")]
    config__delete,
    /// device/list
    #[strum(serialize = "device/list")]
    device__list,
    /// role/list
    #[strum(serialize = "role/list")]
    role__list,
    /// role/write
    #[strum(serialize = "role/write")]
    role__write,
    /// role/delete
    #[strum(serialize = "role/delete")]
    role__delete,
    /// role/assign
    #[strum(serialize = "role/assign")]
    role__assign,
}
