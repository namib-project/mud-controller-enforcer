use rocket::Route;

mod users_dto;
mod users_controller;

pub fn all_routes() -> Vec<Route> {
    users_controller::routes()
}