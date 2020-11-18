use rocket::Route;

mod dtos;
pub(crate) mod mud_controller;
pub(crate) mod users_controller;

pub fn all_routes() -> Vec<Route> {
    users_controller::routes()
}
