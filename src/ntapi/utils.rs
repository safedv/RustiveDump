use super::def::{find_peb, OSVersionInfo};

#[cfg(not(feature = "remote"))]
use crate::{common::utils::unicodestring_to_string, ntapi::def::RtlUserProcessParameters};
#[cfg(not(feature = "remote"))]
use alloc::string::String;

pub unsafe fn rtl_get_version(lp_version_information: &mut OSVersionInfo) -> i32 {
    // Get the pointer to the PEB
    let peb = find_peb();

    if lp_version_information.dw_os_version_info_size
        != core::mem::size_of::<OSVersionInfo>() as u32
    {
        return -1;
    }

    // Fill in the version information from the PEB
    lp_version_information.dw_major_version = (*peb).os_major_version;
    lp_version_information.dw_minor_version = (*peb).os_minor_version;
    lp_version_information.dw_build_number = (*peb).os_build_number;
    lp_version_information.dw_platform_id = (*peb).os_platform_id;
    lp_version_information.sz_csd_version.fill(0);

    0
}

/// Retrieves the current working directory of the process by accessing the Process Environment Block (PEB).
#[cfg(not(feature = "remote"))]
pub fn get_current_directory() -> String {
    unsafe {
        let peb = find_peb();
        if !peb.is_null() {
            let process_parameters = (*peb).process_parameters as *mut RtlUserProcessParameters;
            let cur_dir = &mut process_parameters.as_mut().unwrap().current_directory_path;

            let dir_str = unicodestring_to_string(&(*cur_dir));
            if dir_str.is_some() {
                return dir_str.unwrap();
            }
        }
    }
    String::new()
}

/// Builds an NT path based on the current working directory (cwd) and a file name.
#[cfg(not(feature = "remote"))]
pub fn build_nt_path<'a>(cwd: &str, file_name: &str, buffer: &'a mut [u8]) -> &'a str {
    let mut offset = 0;

    let nt_prefix = b"\\??\\";
    if nt_prefix.len() > buffer.len() {
        // debug_println!("[-] Buffer too small to hold NT prefix.");
        return "";
    }
    buffer[offset..offset + nt_prefix.len()].copy_from_slice(nt_prefix);
    offset += nt_prefix.len();

    let cwd_bytes = cwd.as_bytes();
    if offset + cwd_bytes.len() > buffer.len() {
        // debug_println!("[-] Buffer too small to hold current working directory.");
        return "";
    }
    buffer[offset..offset + cwd_bytes.len()].copy_from_slice(cwd_bytes);
    offset += cwd_bytes.len();

    let file_name_bytes = file_name.as_bytes();
    if offset + file_name_bytes.len() > buffer.len() {
        // debug_println!("[-] Buffer too small to hold file name.");
        return "";
    }
    buffer[offset..offset + file_name_bytes.len()].copy_from_slice(file_name_bytes);
    offset += file_name_bytes.len();

    if let Ok(result_str) = core::str::from_utf8(&buffer[..offset]) {
        result_str
    } else {
        // debug_println!("[-] Failed to convert buffer to UTF-8 string.");
        ""
    }
}
