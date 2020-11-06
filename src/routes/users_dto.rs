use rocket_okapi::JsonSchema;

#[derive(Validate, Serialize, Deserialize, JsonSchema)]
#[schemars(example = "signup_example")]
pub struct SignupDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
}

#[derive(Validate, Serialize, Deserialize, JsonSchema)]
#[schemars(example = "login_example")]
pub struct LoginDto {
    #[validate(length(min = 1, max = 128))]
    pub username: String,
    #[validate(length(min = 6))]
    pub password: String,
}

#[derive(Validate, Serialize, Deserialize, JsonSchema)]
#[schemars(example = "update_password_example")]
pub struct UpdatePasswordDto {
    #[validate(length(min = 6))]
    pub old_password: String,
    #[validate(length(min = 6))]
    pub new_password: String,
}

#[derive(Validate, Serialize, Deserialize, JsonSchema)]
#[schemars(example = "update_user_example")]
pub struct UpdateUserDto {
    #[validate(length(min = 1, max = 128))]
    pub username: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct TokenDto {
    pub token: String,
}

#[derive(Serialize, JsonSchema)]
#[schemars(example = "success_example")]
pub struct SuccessDto {
    pub status: String,
}

#[derive(Serialize, JsonSchema)]
#[schemars(example = "roles_example")]
pub struct RolesDto {
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

fn signup_example() -> SignupDto {
    SignupDto {
        username: String::from("manfred"),
        password: String::from("password123"),
    }
}

fn login_example() -> LoginDto {
    LoginDto {
        username: String::from("manfred"),
        password: String::from("password123"),
    }
}

fn update_password_example() -> UpdatePasswordDto {
    UpdatePasswordDto {
        old_password: String::from("password123"),
        new_password: String::from("newpassword"),
    }
}

fn update_user_example() -> UpdateUserDto {
    UpdateUserDto {
        username: Some(String::from("alfred"))
    }
}

fn success_example() -> SuccessDto {
    SuccessDto {
        status: String::from("ok")
    }
}

fn roles_example() -> RolesDto {
    RolesDto {
        roles: vec![String::from("admin")],
        permissions: vec![String::from("create_device"), String::from("remove_device")],
    }
}