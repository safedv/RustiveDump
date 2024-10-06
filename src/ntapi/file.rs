#[cfg(feature = "verbose")]
use libc_print::libc_println;

use crate::debug_println;

use alloc::vec::Vec;

use super::{def::IoStatusBlock, g_instance::instance};

use super::{
    def::{AccessMask, LargeInteger, ObjectAttributes, UnicodeString},
    utils::{build_nt_path, get_current_directory},
};

pub const SYNCHRONIZE: AccessMask = 0x00100000;
pub const STANDARD_RIGHTS_WRITE: AccessMask = 0x00020000;

pub const FILE_WRITE_DATA: AccessMask = 0x00000002;
pub const FILE_WRITE_ATTRIBUTES: AccessMask = 0x00000100;
pub const FILE_WRITE_EA: AccessMask = 0x00000010;
pub const FILE_APPEND_DATA: AccessMask = 0x00000004;
pub const FILE_GENERIC_WRITE: u32 = STANDARD_RIGHTS_WRITE
    | FILE_WRITE_DATA
    | FILE_WRITE_ATTRIBUTES
    | FILE_WRITE_EA
    | FILE_APPEND_DATA
    | SYNCHRONIZE;
pub const FILE_OVERWRITE_IF: u32 = 0x00000005;

pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;

pub const FILE_SHARE_READ: AccessMask = 0x00000001;
pub const FILE_SHARE_WRITE: AccessMask = 0x00000002;

pub fn save_file(dump_file_bytes: Vec<u8>, dump_file_name: &str) -> i32 {
    use core::{ffi::c_void, ptr::null_mut};

    unsafe {
        let mut handle: *mut c_void = null_mut();

        // Retrieve current directory and handle failure
        let cwd = get_current_directory();
        if cwd.is_empty() {
            debug_println!("[-] Failed to retrieve current working directory");
            return -1;
        }

        let mut buffer = [0u8; 1024];

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

        // Initialize the Unicode string for the registry value name
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

        let mut io_status_block: IoStatusBlock = core::mem::zeroed();

        let allocation_size: *mut LargeInteger = null_mut();

        let desired_access: AccessMask = FILE_GENERIC_WRITE | SYNCHRONIZE;

        let share_access: AccessMask = FILE_SHARE_READ | FILE_SHARE_WRITE;

        let create_options: AccessMask = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

        let create_disposition: AccessMask = FILE_OVERWRITE_IF;

        // Create the file using NtCreateFile
        let status: i32 = instance().ntdll.nt_create_file.run(
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
        );

        if status < 0 {
            debug_println!(
                "[-] Failed to create file with status: NTSTATUS: 0x{:X}",
                status
            );
            return status;
        }

        // Initialize IO_STATUS_BLOCK for NtWriteFile
        let mut io_status_block_write: IoStatusBlock = core::mem::zeroed();

        // Write the file content using NtWriteFile
        let status_write = instance().ntdll.nt_write_file.run(
            handle,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut io_status_block_write,
            dump_file_bytes.as_ptr() as *mut c_void,
            dump_file_bytes.len() as u32,
            null_mut(),
            null_mut(),
        );

        if status_write < 0 {
            debug_println!(
                "[-] Failed to write to file with status: NTSTATUS: 0x{:X}",
                status_write
            );
            instance().ntdll.nt_close.run(handle);
        } else {
            debug_println!(
                "[+] File {} ({}) created successfully.",
                file_name,
                dump_file_bytes.len()
            );
        }

        // Close the file handle
        instance().ntdll.nt_close.run(handle);

        status_write
    }
}
