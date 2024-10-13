use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::{instance::get_instance, native::ntdef::MemoryBasicInformation};

/// Reads memory from a remote process into a buffer.
///
/// Takes a process handle, an address, and the size of the memory to read.
/// Returns a `Vec<u8>` containing the memory contents, or `None` if reading fails.
pub fn read_memory(
    process_handle: *mut c_void,
    address: *mut c_void,
    size: usize,
) -> Option<Vec<u8>> {
    // Allocate a buffer for the memory to be read.
    let mut buffer = vec![0u8; size];
    let mut bytes_read: usize = 0;

    // Perform the memory read operation using the NT API.
    let result = unsafe {
        get_instance().unwrap().ntdll.nt_read_virtual_memory.run(
            process_handle,
            address,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            &mut bytes_read,
        )
    };

    // Return the buffer if successful, otherwise return None.
    if result == 0 && bytes_read > 0 {
        Some(buffer)
    } else {
        None
    }
}

/// Queries information about a memory region in a remote process.
///
/// Returns a `MemoryBasicInformation` struct containing details about the memory region,
/// or `None` if querying fails.
pub fn query_memory_info(
    process_handle: *mut c_void,
    base_address: *mut c_void,
) -> Option<MemoryBasicInformation> {
    let mut mem_info: MemoryBasicInformation = unsafe { core::mem::zeroed() };

    // Query memory information for the given address in the remote process.
    let result = unsafe {
        get_instance().unwrap().ntdll.nt_query_virtual_memory.run(
            process_handle,
            base_address,
            0,
            &mut mem_info as *mut _ as *mut c_void,
            core::mem::size_of::<MemoryBasicInformation>() as usize,
            core::ptr::null_mut(),
        )
    };

    // Return memory information if successful, otherwise return None.
    if result == 0 {
        Some(mem_info)
    } else {
        None
    }
}

/// Reads a wide string (UTF-16) from a remote process's memory.
///
/// Converts the UTF-16 encoded string from the remote process into a `String` and returns it.
/// If reading fails or the string is invalid, returns an empty `String`.
pub fn read_remote_wstr(process_handle: *mut c_void, mem_address: *mut c_void) -> String {
    let mut buffer = vec![0u8; 512]; // Buffer for reading memory.
    let mut bytes_read: usize = 0;

    // Read memory from the remote process.
    let status = unsafe {
        get_instance().unwrap().ntdll.nt_read_virtual_memory.run(
            process_handle,
            mem_address,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            &mut bytes_read,
        )
    };

    if status == 0 {
        let mut u16_vec = Vec::new();
        // Process the buffer in chunks of 2 bytes (for UTF-16 encoding).
        for chunk in buffer.chunks(2) {
            if chunk.len() < 2 {
                break;
            }
            let word = u16::from_le_bytes([chunk[0], chunk[1]]);
            if word == 0 {
                break;
            }
            u16_vec.push(word);
        }
        // Convert the UTF-16 data into a Rust String.
        String::from_utf16(&u16_vec).unwrap_or_else(|_| String::new())
    } else {
        String::new()
    }
}

/// Reads a pointer-sized integer from a remote process's memory.
///
/// Returns the integer value read from the memory address in the remote process,
/// or `0` if the read operation fails.
pub fn read_remote_int_ptr(process_handle: *mut c_void, mem_address: *mut c_void) -> usize {
    let mut buffer = [0u8; 8]; // Buffer for reading an integer (64 bits).
    let mut bytes_read: usize = 0;

    // Read the pointer-sized integer from the remote process.
    let status = unsafe {
        get_instance().unwrap().ntdll.nt_read_virtual_memory.run(
            process_handle,
            mem_address,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            &mut bytes_read,
        )
    };

    // Convert the bytes into a 64-bit unsigned integer and return it as usize.
    if status == 0 {
        let value = u64::from_le_bytes(buffer);
        value as usize
    } else {
        0
    }
}
