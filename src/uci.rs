use core::ptr;
use std::ffi::{CStr, CString};

use snafu::ensure;

use libuci_sys::{uci_alloc_context, uci_context, uci_free_context, uci_option, uci_option_type_UCI_TYPE_STRING, uci_parse_ptr, uci_ptr, uci_type_UCI_TYPE_OPTION};

use crate::error::*;

struct UCI {
    uci_context: *mut uci_context,
}

impl Drop for UCI {
    fn drop(&mut self) {
        unsafe { uci_free_context(self.uci_context) }
    }
}

impl UCI {
    pub fn new() -> Result<UCI> {
        let ctx = unsafe { uci_alloc_context() };
        if ctx.is_null() {
            UCIError {
                message: String::from("Could not alloc uci context"),
            }
            .fail()?
        }
        Ok(UCI { uci_context: ctx })
    }

    pub fn get_str_value(self: &mut Self, key: &str) -> Result<String> {
        let opt = self.get_opt(key)?;
        ensure!(
            opt.type_ != uci_option_type_UCI_TYPE_STRING,
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
        let c_package = unsafe { CStr::from_ptr(pack.e.name) };
        let c_section = unsafe { CStr::from_ptr(sect.e.name) };
        let c_key = unsafe { CStr::from_ptr(opt.e.name) };
        let value = unsafe { CString::from_raw(opt.v.string).into_string()? };

        info!("{}.{}.{}={}", c_package.to_str()?, c_section.to_str()?, c_key.to_str()?, value);
        Ok(value)
    }

    fn get_opt(self: &mut Self, key: &str) -> Result<uci_option> {
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
        let result = unsafe {
            let c_key_bytes = CString::new(key.clone())?.into_raw();
            let r = uci_parse_ptr(self.uci_context, &mut ptr, c_key_bytes);
            let _ = CString::from_raw(c_key_bytes);
            r
        };
        ensure!(
            result == 0,
            UCIError {
                message: format!("Could not parse uci key: {}, {}", key, result),
            }
        );
        ensure!(
            !ptr.last.is_null(),
            UCIError {
                message: format!("Cannot get string value of null value: {}", key),
            }
        );
        let last;
        unsafe {
            last = *ptr.last;
        }
        ensure!(
            last.type_ == uci_type_UCI_TYPE_OPTION && !ptr.o.is_null(),
            UCIError {
                message: format!("Cannot get value of non-option: {}", key),
            }
        );
        Ok(unsafe { *ptr.o })
    }
}
