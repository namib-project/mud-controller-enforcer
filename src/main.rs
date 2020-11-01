use namib_shared as shared;

fn main() {
    let user = shared::user::User {
        name: String::from("Bob"),
        admin: true
    };
    println!("[Controller] Here is the user '{}'. Nice name!", user.name);
}
