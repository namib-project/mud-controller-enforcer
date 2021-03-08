use paperclip::actix::Apiv2Schema;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct RoleAssignDto {
    /// Name of the role
    pub name: String,
    /// User id
    pub id: i64,
}
