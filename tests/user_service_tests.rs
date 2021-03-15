mod lib;

use namib_mud_controller::{error::Result, models::User, services::user_service};

#[actix_rt::test]
async fn test_creating_admin_user() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_creating_admin_user").await;

    let user_id = user_service::insert(User::new("admin".to_string(), "password")?, &ctx.db_conn).await?;
    let user = user_service::find_by_id(user_id, &ctx.db_conn).await?;

    assert!(user.roles.iter().any(|r| r == "admin"));
    assert!(user.permissions.iter().any(|p| p == "**"));

    let user_id = user_service::insert(User::new("not_admin".to_string(), "password")?, &ctx.db_conn).await?;
    let user = user_service::find_by_id(user_id, &ctx.db_conn).await?;

    assert!(user.roles.is_empty());
    assert!(user.permissions.is_empty());

    Ok(())
}
