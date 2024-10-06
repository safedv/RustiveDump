#[cfg(feature = "verbose")]
use libc_print::libc_println;

use core::{ffi::c_void, ptr::null_mut};

use crate::debug_println;

use super::{
    def::{TokenPrivileges, LUID},
    g_instance::instance,
};

/// This function enables the SeDebugPrivilege privilege using the NT API.
pub unsafe fn enable_se_debug_privilege() -> i32 {
    const TOKEN_ADJUST_PRIVILEGES: u32 = 32u32;
    const TOKEN_QUERY: u32 = 8u32;

    let current_process_handle = -1isize as *mut c_void;
    let mut token_handle: *mut c_void = null_mut();

    // Open the process token.
    let ntstatus = instance().ntdll.nt_open_process_token.run(
        current_process_handle,
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &mut token_handle,
    );

    if ntstatus != 0 {
        debug_println!(
            "[-] Error calling NtOpenProcessToken. NTSTATUS: 0x{:X}",
            ntstatus
        );
        return ntstatus;
    }

    let luid = LUID {
        low_part: 20,
        high_part: 0,
    };

    let mut token_privileges = TokenPrivileges {
        privilege_count: 1,
        luid: luid,
        attributes: 0x00000002,
    };

    // Adjust token privileges to enable SeDebugPrivilege.
    let ntstatus = instance().ntdll.nt_adjust_privileges_token.run(
        token_handle,
        false,
        &mut token_privileges,
        core::mem::size_of::<TokenPrivileges>() as u32,
        null_mut(),
        null_mut(),
    );

    if ntstatus != 0 {
        debug_println!(
            "[-] Error calling NtAdjustPrivilegesToken. NTSTATUS: 0x{:X}",
            ntstatus
        );
        return ntstatus;
    }

    ntstatus
}
