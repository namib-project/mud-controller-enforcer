#[cfg(not(debug_assertions))]
const GIT_BRANCH: Option<&str> = option_env!("CI_COMMIT_REF_SLUG");
#[cfg(not(debug_assertions))]
const GIT_COMMIT: Option<&str> = option_env!("CI_COMMIT_SHORT_SHA");

fn main() {
    #[cfg(not(debug_assertions))]
    if GIT_BRANCH.is_none() {
        println!("cargo:rustc-env=CI_COMMIT_REF_SLUG=undefined")
    }
    #[cfg(not(debug_assertions))]
    if GIT_COMMIT.is_none() {
        println!("cargo:rustc-env=CI_COMMIT_SHORT_SHA=undefined")
    }
}
