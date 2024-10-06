#[cfg(feature = "verbose")]
use libc_print::libc_println;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::{
    common::utils::dbj2_hash,
    debug_println,
    mdfile::ModuleInfo,
    ntapi::def::{MemoryBasicInformation, ProcessBasicInformation},
};

use super::g_instance::instance;

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
        instance().ntdll.nt_read_virtual_memory.run(
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
        instance().ntdll.nt_query_virtual_memory.run(
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
        instance().ntdll.nt_read_virtual_memory.run(
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
        instance().ntdll.nt_read_virtual_memory.run(
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

/// Retrieves the list of loaded modules in a process's memory.
///
/// Uses the process handle to query the PEB (Process Environment Block) and retrieves
/// information about the loaded modules in the process. Optionally filters modules by a hash.
pub fn get_modules_info(process_handle: *mut c_void, module_hash: Option<u32>) -> Vec<ModuleInfo> {
    let mut process_information: ProcessBasicInformation = unsafe { core::mem::zeroed() };
    let mut return_length: u32 = 0;

    // Query the process information to get the PEB base address.
    let status = unsafe {
        instance().ntdll.nt_query_information_process.run(
            process_handle as *mut c_void,
            0, // ProcessBasicInformation
            &mut process_information as *mut _ as *mut c_void,
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        )
    };

    if status != 0 {
        panic!("[-] Failed to query process information.");
    }

    debug_println!(
        "[+] PEB Base Address: 0x{:x}",
        process_information.peb_base_address as usize
    );

    // Compute the address of the loader's data structure from the PEB.
    let ldr_offset = 0x18;
    let ldr_pointer = (process_information.peb_base_address as usize + ldr_offset) as *mut c_void;
    let ldr_address = read_remote_int_ptr(process_handle, ldr_pointer);

    // Get the address of the module list from the loader data.
    let in_initialization_order_module_list_offset = 0x30;
    let module_list_address =
        (ldr_address + in_initialization_order_module_list_offset) as *mut c_void;
    let mut next_flink = read_remote_int_ptr(process_handle, module_list_address);

    // Offsets within the LDR module structure.
    let flink_dllbase_offset = 0x20;
    let flink_buffer_fulldllname_offset = 0x40;
    let flink_buffer_offset = 0x50;

    let mut module_info_arr: Vec<ModuleInfo> = Vec::new();
    let mut dll_base = 1337;

    // Loop through the module list until the base address is zero.
    while dll_base != 0 {
        next_flink -= 0x10;

        // Read the base address of the module.
        dll_base = read_remote_int_ptr(
            process_handle,
            (next_flink + flink_dllbase_offset) as *mut c_void,
        );
        if dll_base == 0 {
            break;
        }

        // Read the base and full DLL names from memory.
        let base_dll_name_ptr = read_remote_int_ptr(
            process_handle,
            (next_flink + flink_buffer_offset) as *mut c_void,
        ) as *mut c_void;
        let base_dll_name = read_remote_wstr(process_handle, base_dll_name_ptr);

        let full_dll_name_ptr = read_remote_int_ptr(
            process_handle,
            (next_flink + flink_buffer_fulldllname_offset) as *mut c_void,
        ) as *mut c_void;
        let full_dll_name = read_remote_wstr(process_handle, full_dll_name_ptr);

        // If a module hash is provided, filter by hash; otherwise, include all modules.
        match module_hash {
            Some(value) => {
                if value == dbj2_hash(base_dll_name.clone().as_bytes()) {
                    module_info_arr.push(ModuleInfo {
                        base_name: base_dll_name,
                        full_dll_name,
                        base_address: dll_base,
                        region_size: 0,
                    });

                    break; // Stop searching after finding the matching module.
                }
            }
            None => {
                module_info_arr.push(ModuleInfo {
                    base_name: base_dll_name,
                    full_dll_name,
                    base_address: dll_base,
                    region_size: 0,
                });
            }
        }

        // Move to the next module in the list.
        next_flink = read_remote_int_ptr(process_handle, (next_flink + 0x10) as *mut c_void);
    }

    module_info_arr
}
