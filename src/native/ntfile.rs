use core::ffi::c_ulong;

use crate::{debug_println, instance::get_instance};

use alloc::{string::String, vec::Vec};

use super::ntdef::{
    find_peb, IoStatusBlock, LargeInteger, ObjectAttributes, RtlUserProcessParameters,
    UnicodeString,
};

pub const SYNCHRONIZE: c_ulong = 0x00100000;
pub const STANDARD_RIGHTS_WRITE: c_ulong = 0x00020000;

pub const FILE_WRITE_DATA: c_ulong = 0x00000002;
pub const FILE_WRITE_ATTRIBUTES: c_ulong = 0x00000100;
pub const FILE_WRITE_EA: c_ulong = 0x00000010;
pub const FILE_APPEND_DATA: c_ulong = 0x00000004;
pub const FILE_GENERIC_WRITE: u32 = STANDARD_RIGHTS_WRITE
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | SYNCHRONIZE;
pub const FILE_OVERWRITE_IF: u32 = 0x00000005;

pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;

pub const FILE_SHARE_READ: c_ulong = 0x00000001;
pub const FILE_SHARE_WRITE: c_ulong = 0x00000002;

pub fn save_file(dump_file_bytes: Vec<u8>, dump_file_name: &str) -> i32 {
    use core::{ffi::c_void, ptr::null_mut};

    let mut handle: *mut c_void = null_mut();

    // Retrieve current directory and handle failure
    let cwd = get_current_directory();
    if cwd.is_empty() {
        debug_println!("[-] Failed to retrieve current working directory");
        return -1;
    }

    let mut buffer = [0u8; 512];

    // Build NT path and handle failure
    let file_name = build_nt_path(&cwd, dump_file_name, &mut buffer);
    if file_name.is_empty() {
        debug_println!("[-] Failed to build NT path for file");
        return -1;
    }

    let file_path: Vec<u16> = {
        let mut vec = Vec::with_capacity(file_name.len() + 1);
        for c in file_name.encode_utf16() {
            vec.push(c);
        }
        vec.push(0);
        vec
    };

    // Initialize a Unicode string for the file path
    let mut unicode_string = UnicodeString::new();
    unicode_string.init(file_path.as_ptr());

    let mut object_attributes = ObjectAttributes::new();
    ObjectAttributes::initialize(
        &mut object_attributes,
        &mut unicode_string, // NT path name
        0,                   // Flags for case-insensitivity and inheritance
        null_mut(),          // No root directory
        null_mut(),          // No security descriptor
    );

    let mut io_status_block: IoStatusBlock = unsafe { core::mem::zeroed() };

    let allocation_size: *mut LargeInteger = null_mut();

    let desired_access: c_ulong = FILE_GENERIC_WRITE | SYNCHRONIZE;

    let share_access: c_ulong = FILE_SHARE_READ | FILE_SHARE_WRITE;

    let create_options: c_ulong = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

    let create_disposition: c_ulong = FILE_OVERWRITE_IF;

    // Create the file using NtCreateFile
    let status: i32 = unsafe {
        get_instance().unwrap().ntdll.nt_create_file.run(
            &mut handle,
            desired_access,
            &mut object_attributes,
            &mut io_status_block,
            allocation_size,
            0,
            share_access,
            create_disposition,
            create_options,
            null_mut(),
            0,
        )
    };

    if status < 0 {
        debug_println!("[-] Failed to create file with status: ", status);
        return status;
    }

    // Initialize IO_STATUS_BLOCK for NtWriteFile
    let mut io_status_block_write: IoStatusBlock = unsafe { core::mem::zeroed() };

    // Write the file content using NtWriteFile
    let status_write = unsafe {
        get_instance().unwrap().ntdll.nt_write_file.run(
            handle,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut io_status_block_write,
            dump_file_bytes.as_ptr() as *mut c_void,
            dump_file_bytes.len() as u32,
            null_mut(),
            null_mut(),
        )
    };

    if status_write < 0 {
        debug_println!("[-] Failed to write to file with status: ", status_write);
        unsafe { get_instance().unwrap().ntdll.nt_close.run(handle) };
    } else {
        debug_println!("[+] File created successfully!");
    }

    // Close the file handle
    unsafe { get_instance().unwrap().ntdll.nt_close.run(handle) };

    status_write
}

pub fn unicodestring_to_string(unicode_string: &UnicodeString) -> Option<String> {
    if unicode_string.length == 0 || unicode_string.buffer.is_null() {
        return None;
    }

    let slice = unsafe {
        core::slice::from_raw_parts(unicode_string.buffer, (unicode_string.length / 2) as usize)
    };

    String::from_utf16(slice).ok()
}

/// Retrieves the current working directory of the process by accessing the Process Environment Block (PEB).
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
pub fn build_nt_path<'a>(cwd: &str, file_name: &str, buffer: &'a mut [u8]) -> &'a str {
    let mut offset = 0;

    let nt_prefix = b"\\??\\";
    if nt_prefix.len() > buffer.len() {
        debug_println!(
            "[-] Buffer too small to hold NT prefix. Length: ",
            buffer.len(),
            false
        );
        return "";
    }
    buffer[offset..offset + nt_prefix.len()].copy_from_slice(nt_prefix);
    offset += nt_prefix.len();

    let cwd_bytes = cwd.as_bytes();
    if offset + cwd_bytes.len() > buffer.len() {
        debug_println!(
            "[-] Buffer too small to hold current working directory. Length: ",
            buffer.len(),
            false
        );
        return "";
    }
    buffer[offset..offset + cwd_bytes.len()].copy_from_slice(cwd_bytes);
    offset += cwd_bytes.len();

    let file_name_bytes = file_name.as_bytes();
    if offset + file_name_bytes.len() > buffer.len() {
        debug_println!(
            "[-] Buffer too small to hold file name. Length: ",
            buffer.len(),
            false
        );
        return "";
    }
    buffer[offset..offset + file_name_bytes.len()].copy_from_slice(file_name_bytes);
    offset += file_name_bytes.len();

    if let Ok(result_str) = core::str::from_utf8(&buffer[..offset]) {
        result_str
    } else {
        debug_println!("[-] Failed to convert buffer to UTF-8 string.");
        ""
    }
}
