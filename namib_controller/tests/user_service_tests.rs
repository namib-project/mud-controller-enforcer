mod lib;

use namib_controller::{error::Result, models::User, services::user_service};

#[tokio::test(flavor = "multi_thread")]
async fn test_creating_admin_user() -> Result<()> {
    let ctx = lib::IntegrationTestContext::new("test_creating_admin_user").await;

    let admin_id = user_service::insert(User::new("admin".to_string(), "password")?, &ctx.db_conn).await?;
    let admin = user_service::find_by_id(admin_id, &ctx.db_conn).await?;

    assert!(admin.roles.iter().any(|r| r.name == "admin"));
    assert!(admin.permissions.iter().any(|p| p == "**"));

    let user_id = user_service::insert(User::new("not_admin".to_string(), "password")?, &ctx.db_conn).await?;
    let user = user_service::find_by_id(user_id, &ctx.db_conn).await?;

    assert!(user.roles.is_empty());
    assert!(user.permissions.is_empty());

    let users = user_service::get_all(&ctx.db_conn).await?;
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].roles, admin.roles);
    assert_eq!(users[1].roles, user.roles);

    Ok(())
}
