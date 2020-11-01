use namib_shared as shared;

fn main() {
    let user = shared::user::User {
        name: String::from("Alice"),
        admin: true
    };
    println!("[Enforcer] Here is the user '{}'. Nice name!", user.name);
}
