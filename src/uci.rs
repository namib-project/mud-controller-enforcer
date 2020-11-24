#[cfg(not(unix))]
pub use mock::*;
#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
#[allow(clippy::shadow_unrelated)]
mod unix {
    use core::ptr;
    use std::{
        ffi::{CStr, CString},
        ops::{Deref, DerefMut},
    };

    use snafu::ensure;

    use libuci_sys::{
        uci_alloc_context, uci_commit, uci_context, uci_delete, uci_free_context, uci_get_errorstr, uci_lookup_ptr, uci_option_type_UCI_TYPE_STRING, uci_ptr,
        uci_ptr_UCI_LOOKUP_COMPLETE, uci_revert, uci_save, uci_set, uci_set_confdir, uci_type_UCI_TYPE_OPTION, uci_type_UCI_TYPE_SECTION, uci_unload,
    };

    use crate::error::{Result, UCIError};

    #[allow(clippy::cast_possible_wrap)]
    const UCI_OK: i32 = libuci_sys::UCI_OK as i32;

    /// Contains the native `uci_context`
    pub struct UCI(*mut uci_context);

    impl Drop for UCI {
        fn drop(&mut self) {
            unsafe { uci_free_context(self.0) }
        }
    }

    /// Contains the native `uci_ptr` and it's raw `CString` key
    /// this is done so the raw `CString` stays alive until the `uci_ptr` is dropped
    struct UciPtr(uci_ptr, *mut i8);

    impl Deref for UciPtr {
        type Target = uci_ptr;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for UciPtr {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl Drop for UciPtr {
        fn drop(&mut self) {
            unsafe { CString::from_raw(self.1) };
        }
    }

    impl UCI {
        /// Creates a new UCI context.
        /// The C memory will be freed when the object is dropped.
        pub fn new() -> Result<UCI> {
            let ctx = unsafe { uci_alloc_context() };
            ensure!(
                !ctx.is_null(),
                UCIError {
                    message: String::from("Could not alloc uci context"),
                }
            );
            Ok(UCI(ctx))
        }

        /// Sets the config directory of UCI, this is `/etc/config` by default.
        pub fn set_config_dir(&mut self, config_dir: &str) -> Result<()> {
            let result = unsafe {
                let raw = CString::new(config_dir)?;
                uci_set_confdir(self.0, raw.as_bytes_with_nul().as_ptr() as *const i8)
            };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Cannot set config dir: {}, {}",
                        config_dir,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    )
                }
            );
            info!("Set config dir to: {}", config_dir);
            Ok(())
        }

        /// Delete an option or section in UCI.
        /// UCI will keep the delta changes in a temporary location until `commit()` or `revert()` is called.
        ///
        /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
        ///
        /// if the deletion failed an `Err` is returned.
        pub fn delete(&mut self, identifier: &str) -> Result<()> {
            let mut ptr = self.get_ptr(identifier)?;
            let result = unsafe { uci_delete(self.0, &mut ptr.0) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not delete uci key: {}, {}, {}",
                        identifier,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            let result = unsafe { uci_save(self.0, ptr.p) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not save uci key: {}, {}, {}",
                        identifier,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            Ok(())
        }

        /// Revert changes to an option, section or package
        ///
        /// Allowed keys are like `network`, `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
        ///
        /// if the deletion failed an `Err` is returned.
        pub fn revert(&mut self, identifier: &str) -> Result<()> {
            let mut ptr = self.get_ptr(identifier)?;
            let result = unsafe { uci_revert(self.0, &mut ptr.0) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not revert uci key: {}, {}, {}",
                        identifier,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            let result = unsafe { uci_save(self.0, ptr.p) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not save uci key: {}, {}, {}",
                        identifier,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            Ok(())
        }

        /// Sets an option value or section type in UCI, creates the key if necessary.
        /// UCI will keep the delta changes in a temporary location until `commit()` or `revert()` is called.
        ///
        /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.wan` and `network.@interface[-1]`
        ///
        /// if the assignment failed an `Err` is returned.
        pub fn set(&mut self, identifier: &str, val: &str) -> Result<()> {
            ensure!(
                !val.contains('\''),
                UCIError {
                    message: format!("Values may not contain quotes: {}={}", identifier, val)
                }
            );
            let mut ptr = self.get_ptr(format!("{}={}", identifier, val).as_ref())?;
            ensure!(
                !ptr.value.is_null(),
                UCIError {
                    message: format!("parsed value is null: {}={}", identifier, val)
                }
            );
            let result = unsafe { uci_set(self.0, &mut ptr.0) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not set uci key: {}={}, {}, {}",
                        identifier,
                        val,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            let result = unsafe { uci_save(self.0, ptr.p) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not save uci key: {}={}, {}, {}",
                        identifier,
                        val,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            Ok(())
        }

        /// Commit all changes to the specified package
        /// writing the temporary delta to the config file
        pub fn commit(&mut self, package: &str) -> Result<()> {
            let mut ptr = self.get_ptr(package)?;
            let result = unsafe { uci_commit(self.0, &mut ptr.p, false) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not set commit uci package: {}, {}, {}",
                        package,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            if !ptr.p.is_null() {
                unsafe {
                    uci_unload(self.0, ptr.p);
                }
            }
            Ok(())
        }

        /// Queries an option value or section type from UCI.
        /// If a key has been changed in the delta, the updated value will be returned.
        ///
        /// Allowed keys are like `network.wan.proto`, `network.@interface[-1].iface`, `network.lan` and `network.@interface[-1]`
        ///
        /// if the entry does not exist an `Err` is returned.
        pub fn get(&mut self, key: &str) -> Result<String> {
            let ptr = self.get_ptr(key)?;
            ensure!(
                ptr.flags & uci_ptr_UCI_LOOKUP_COMPLETE != 0,
                UCIError {
                    message: format!("Lookup failed: {}", key),
                }
            );
            let last = unsafe { *ptr.last };
            #[allow(non_upper_case_globals)]
            match last.type_ {
                uci_type_UCI_TYPE_OPTION => {
                    let opt = unsafe { *ptr.o };
                    ensure!(
                        opt.type_ == uci_option_type_UCI_TYPE_STRING,
                        UCIError {
                            message: format!("Cannot get string value of non-string: {} {}", key, opt.type_),
                        }
                    );
                    ensure!(
                        !opt.section.is_null(),
                        UCIError {
                            message: format!("uci section was null: {}", key)
                        }
                    );
                    let sect = unsafe { *opt.section };
                    ensure!(
                        !sect.package.is_null(),
                        UCIError {
                            message: format!("uci package was null: {}", key)
                        }
                    );
                    let pack = unsafe { *sect.package };
                    let value = unsafe { CStr::from_ptr(opt.v.string).to_str()? };

                    debug!(
                        "{}.{}.{}={}",
                        unsafe { CStr::from_ptr(pack.e.name) }.to_str()?,
                        unsafe { CStr::from_ptr(sect.e.name) }.to_str()?,
                        unsafe { CStr::from_ptr(opt.e.name) }.to_str()?,
                        value
                    );
                    Ok(String::from(value))
                },
                uci_type_UCI_TYPE_SECTION => {
                    let sect = unsafe { *ptr.s };
                    ensure!(
                        !sect.package.is_null(),
                        UCIError {
                            message: format!("uci package was null: {}", key)
                        }
                    );
                    let pack = unsafe { *sect.package };
                    let typ = unsafe { CStr::from_ptr(sect.type_).to_str()? };

                    debug!(
                        "{}.{}={}",
                        unsafe { CStr::from_ptr(pack.e.name) }.to_str()?,
                        unsafe { CStr::from_ptr(sect.e.name) }.to_str()?,
                        typ
                    );
                    Ok(String::from(typ))
                },
                _ => UCIError {
                    message: format!("unsupported type: {}", last.type_),
                }
                .fail()?,
            }
        }

        /// Queries UCI (e.g. `package.section.key`)
        ///
        /// This also supports advanced syntax like `network.@interface[-1].ifname` (get ifname of last interface)
        ///
        /// An `Ok(result)` is guaranteed to be a valid ptr and ptr.last will be set.
        ///
        /// If the key could not be found `ptr.flags & UCI_LOOKUP_COMPLETE` will not be set, but the ptr is still valid.
        ///
        /// If `identifier` is assignment like `network.wan.proto="dhcp"`, `ptr.value` will be set.
        fn get_ptr(&mut self, identifier: &str) -> Result<UciPtr> {
            let mut ptr = uci_ptr {
                target: 0,
                flags: 0,
                p: ptr::null_mut(),
                s: ptr::null_mut(),
                o: ptr::null_mut(),
                last: ptr::null_mut(),
                package: ptr::null(),
                section: ptr::null(),
                option: ptr::null(),
                value: ptr::null(),
            };
            let raw = CString::new(identifier)?.into_raw();
            let result = unsafe { uci_lookup_ptr(self.0, &mut ptr, raw, true) };
            ensure!(
                result == UCI_OK,
                UCIError {
                    message: format!(
                        "Could not parse uci key: {}, {}, {}",
                        identifier,
                        result,
                        self.get_last_error().unwrap_or_else(|_| String::from("Unknown"))
                    ),
                }
            );
            debug!("{:?}", ptr);
            ensure!(
                !ptr.last.is_null(),
                UCIError {
                    message: format!("Cannot access null value: {}", identifier),
                }
            );
            Ok(UciPtr(ptr, raw))
        }

        /// Obtains the most recent error from UCI as a string
        /// if no `last_error` is set, an `Err` is returned.
        fn get_last_error(&mut self) -> Result<String> {
            let mut raw: *mut std::os::raw::c_char = ptr::null_mut();
            unsafe { uci_get_errorstr(self.0, &mut raw, ptr::null()) };
            ensure!(
                !raw.is_null(),
                UCIError {
                    message: String::from("last_error was null"),
                }
            );
            match unsafe { CStr::from_ptr(raw) }.to_str() {
                Ok(o) => {
                    let s = String::from(o);
                    unsafe { libc::free(raw as *mut std::os::raw::c_void) };
                    Ok(s)
                },
                Err(e) => {
                    unsafe { libc::free(raw as *mut std::os::raw::c_void) };
                    Err(e.into())
                },
            }
        }
    }
}

#[cfg(not(unix))]
#[allow(clippy::unused_self)]
mod mock {
    use crate::error::Result;

    pub struct UCI {}

    impl UCI {
        pub fn new() -> Result<UCI> {
            Ok(UCI {})
        }

        pub fn set_config_dir(&mut self, config_dir: &str) -> Result<()> {
            info!("set_config_dir {}", config_dir);
            Ok(())
        }

        pub fn revert(&mut self, package: &str) -> Result<()> {
            info!("revert {}", package);
            Ok(())
        }

        pub fn delete(&mut self, key: &str) -> Result<()> {
            info!("delete {}", key);
            Ok(())
        }

        pub fn get(&mut self, key: &str) -> Result<String> {
            info!("get {}", key);
            Ok(format!("{}_value", key))
        }

        pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
            info!("set {}={}", key, value);
            Ok(())
        }

        pub fn commit(&mut self, package: &str) -> Result<()> {
            info!("commit {}", package);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File, io::Read};

    use crate::error::Result;

    use super::*;

    fn init() -> Result<UCI> {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).is_test(true).try_init();

        let mut uci = UCI::new()?;
        uci.set_config_dir("tests/config")?;

        Ok(uci)
    }

    #[test]
    fn test_reading_key() -> Result<()> {
        let mut uci = init()?;

        assert_eq!(uci.get("network.wan")?, "interface");
        assert_eq!(uci.get("network.@interface[0]")?, "interface");
        assert_eq!(uci.get("network.a")?, "alias");
        assert_eq!(uci.get("network.@alias[-1]")?, "alias");
        assert_eq!(uci.get("network.wan.proto")?, "dhcp");
        assert_eq!(uci.get("network.@interface[-1].proto")?, "dhcp");
        assert_eq!(uci.get("network.lan.proto")?, "static");
        assert_eq!(uci.get("network.@interface[0].proto")?, "static");
        assert_eq!(uci.get("broken.a").is_err(), true);
        assert_eq!(uci.get("broken.a.b").is_err(), true);
        assert_eq!(uci.get("inexistant.c").is_err(), true);
        assert_eq!(uci.get("inexistant.c.d").is_err(), true);
        Ok(())
    }

    #[test]
    fn test_writing_key() -> Result<()> {
        let mut uci = init()?;

        File::create("tests/config/new_network")?;

        uci.set("new_network.a", "alias")?;
        uci.set("new_network.a.interface", "lan")?;
        uci.set("new_network.b", "alias")?;
        uci.set("new_network.b.interface", "lan")?;
        uci.set("new_network.lan", "interface")?;
        uci.set("new_network.lan.proto", "static")?;
        uci.set("new_network.lan.ifname", "eth0")?;
        uci.set("new_network.lan.test", "123")?;
        uci.set("new_network.lan.enabled", "off")?;
        uci.set("new_network.lan.ipaddr", "2.3.4.5")?;
        uci.set("new_network.wan", "interface")?;
        uci.set("new_network.wan.proto", "dhcp")?;
        uci.set("new_network.wan.ifname", "eth1")?;
        uci.set("new_network.wan.enabled", "on")?;
        uci.set("new_network.wan.aliases", "c d")?;
        uci.set("new_network.c", "alias")?;
        uci.set("new_network.c.interface", "wan")?;
        uci.set("new_network.d", "alias")?;
        uci.set("new_network.d.interface", "wan")?;
        uci.commit("new_network")?;

        let mut file = File::open("tests/config/new_network")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut file = File::open("tests/config/network")?;
        let mut actual_contents = String::new();
        file.read_to_string(&mut actual_contents)?;

        fs::remove_file("tests/config/new_network")?;

        assert_eq!(contents, actual_contents);
        Ok(())
    }

    #[test]
    fn test_delete() -> Result<()> {
        let mut uci = init()?;

        assert_eq!(uci.get("network.wan.proto")?, "dhcp");
        assert_eq!(uci.get("network.wan.ifname")?, "eth1");
        uci.delete("network.wan")?;
        assert_eq!(uci.get("network.wan.proto").is_err(), true);
        assert_eq!(uci.get("network.wan.ifname").is_err(), true);
        uci.revert("network")?;
        assert_eq!(uci.get("network.wan.proto")?, "dhcp");
        assert_eq!(uci.get("network.wan.ifname")?, "eth1");
        Ok(())
    }
}
