#[cfg(feature = "verbose")]
use libc_print::libc_println;

use alloc::vec::Vec;
use core::{ffi::c_void, ptr::null_mut};

use crate::{common::utils::dbj2_hash, debug_println};

use super::{
    def::{
        AccessMask, ClientId, ObjectAttributes, SystemProcessInformation, OBJ_CASE_INSENSITIVE,
        STATUS_INFO_LENGTH_MISMATCH,
    },
    g_instance::instance,
};

/// Takes a snapshot of the currently running processes.
///
/// This function utilizes the `NtQuerySystemInformation` function from the NT API to retrieve
/// information about all processes currently running on the system. It first determines the necessary
/// buffer size, then allocates memory, and finally retrieves the process information.
pub unsafe fn nt_process_snapshot(
    snapshot: &mut *mut SystemProcessInformation,
    size: &mut usize,
) -> i32 {
    let mut length: u32 = 0;

    // First call to determine the required length of the buffer for process information.
    let mut status =
        instance()
            .ntdll
            .nt_query_system_information
            .run(5, null_mut(), 0, &mut length);

    // Check if the call returned STATUS_INFO_LENGTH_MISMATCH (expected) or another error.
    if status != STATUS_INFO_LENGTH_MISMATCH && status != 0 {
        return status;
    }

    // Allocate memory for the SystemProcessInformation structure.
    let mut buffer = Vec::new();
    buffer.resize(length as usize, 0);

    // Second call to actually retrieve the process information into the allocated buffer.
    status = instance().ntdll.nt_query_system_information.run(
        5,
        buffer.as_mut_ptr() as *mut c_void,
        length,
        &mut length,
    );

    // Check if the process information retrieval was successful.
    if status != 0 {
        return status;
    }

    // Cast the buffer to the SystemProcessInformation structure.
    *snapshot = buffer.as_mut_ptr() as *mut SystemProcessInformation;
    *size = length as usize;

    // Keep the buffer alive by preventing its deallocation.
    core::mem::forget(buffer);

    status
}

/// Retrieves a handle to a process with the specified PID and desired access rights using the NT API.
///
/// This function opens a handle to a target process by specifying its process ID (PID) and the desired access rights.
/// The syscall `NtOpenProcess` is used to obtain the handle, and the function initializes the required structures
/// (`OBJECT_ATTRIBUTES` and `CLIENT_ID`) needed to make the system call.
pub unsafe fn get_process_handle(pid: i32, desired_access: AccessMask) -> *mut c_void {
    let mut process_handle: *mut c_void = null_mut();

    // Initialize object attributes for the process, setting up the basic structure with default options.
    let mut object_attributes = ObjectAttributes::new();

    ObjectAttributes::initialize(
        &mut object_attributes,
        null_mut(),           // No name for the object.
        OBJ_CASE_INSENSITIVE, // Case-insensitive name comparison.
        null_mut(),           // No root directory.
        null_mut(),           // No security descriptor.
    );

    // Initialize client ID structure with the target process ID.
    let mut client_id = ClientId::new();
    client_id.unique_process = pid as _;

    // Perform a system call to NtOpenProcess to obtain a handle to the specified process.
    instance().ntdll.nt_open_process.run(
        &mut process_handle,
        desired_access,
        &mut object_attributes,
        &mut client_id as *mut _ as *mut c_void,
    );

    process_handle
}

/// Retrieves a handle to a process with the specified name hash and desired access rights using the NT API.
///
/// This function takes a process name hash, searches for its process ID (PID) using the `process_snapshot` function,
/// and then opens a handle to the process using `NtOpenProcess`.
pub unsafe fn get_process_handle_by_name(name: u32, desired_access: AccessMask) -> *mut c_void {
    let mut snapshot: *mut SystemProcessInformation = null_mut();
    let mut size: usize = 0;

    // Take a snapshot of all currently running processes.
    let status = nt_process_snapshot(&mut snapshot, &mut size);

    if status != 0 {
        debug_println!(
            "Failed to retrieve process snapshot: NTSTATUS: 0x{:X}",
            status
        );
        return null_mut();
    }

    let mut current = snapshot;
    while !current.is_null() {
        // Get the address of the process name.
        let name_addr = (*current).image_name.buffer;
        let name_len = (*current).image_name.length as usize;

        // Only compare if the process has a name.
        if !name_addr.is_null() && name_len > 0 {
            // Convert the process name to a byte slice.
            let name_slice: &[u8] = core::slice::from_raw_parts(name_addr as _, name_len);

            // Calculate the hash of the process name.
            let hash = dbj2_hash(name_slice);

            // If the hash matches the provided hash, open a handle to the process.
            if name == hash {
                return get_process_handle((*current).unique_process_id as i32, desired_access);
            }
        }

        // Move to the next process in the list.
        if (*current).next_entry_offset == 0 {
            break;
        }
        current = (current as *const u8).add((*current).next_entry_offset as usize)
            as *mut SystemProcessInformation;
    }

    null_mut()
}
