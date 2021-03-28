mod lib;
use namib_mud_controller::{
    error::{Error, Result},
    models::User,
    routes::dtos::RoleUpdateDto,
    services::{role_service, user_service},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_inserting_role_mappings() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_inserting_role_mappings").await;
    let user_id = user_service::insert(User::new("admin".to_string(), "pass")?, &ctx.db_conn).await?;
    let role = role_service::role_create(
        &ctx.db_conn,
        RoleUpdateDto {
            name: "some name".to_string(),
            permissions: vec!["some_permission".to_string()],
        },
    )
    .await?;

    // try inserting relation with role_id that doesn't exist
    // this should result in a DatabaseError
    match role_service::role_add_to_user(&ctx.db_conn, user_id, 37).await {
        Err(Error::DatabaseError { .. }) => {},
        _ => panic!(),
    }

    // this should work though
    role_service::role_add_to_user(&ctx.db_conn, user_id, role.id).await
}
