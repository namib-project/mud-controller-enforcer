use paperclip::actix::Apiv2Schema;

#[derive(Validate, Debug, Serialize, Deserialize, Apiv2Schema)]
pub struct RoleAssignDto {
    /// Id of the role
    pub role_id: i64,
    /// User id
    pub user_id: i64,
}
