use crate::native::{ntapi::NtDll, ntdef::find_peb};

#[cfg(feature = "debug")]
use crate::debug::k32::Kernel32;

#[cfg(feature = "remote")]
use crate::remote::winsock::Winsock;

// A magic number to identify a valid `Instance` struct
pub const INSTANCE_MAGIC: u32 = 0x17171717;

#[repr(C)]
// The main structure holding system API modules and the magic value
pub struct Instance {
    pub magic: u32,   // Unique value to identify a valid instance
    pub ntdll: NtDll, // NtDll API functions

    #[cfg(feature = "debug")]
    pub k32: Kernel32, // Kernel32 API functions

    #[cfg(feature = "remote")]
    pub winsock: Winsock, // Winsock API functions
}

impl Instance {
    pub fn new() -> Self {
        Instance {
            magic: INSTANCE_MAGIC,
            ntdll: NtDll::new(),

            #[cfg(feature = "debug")]
            k32: Kernel32::new(),

            #[cfg(feature = "remote")]
            winsock: Winsock::new(),
        }
    }
}

/// Attempts to locate the global `Instance` by scanning process heaps and
/// returns a mutable reference to it if found.
pub unsafe fn get_instance() -> Option<&'static mut Instance> {
    let peb = find_peb(); // Locate the PEB (Process Environment Block)
    let process_heaps = (*peb).process_heaps;
    let number_of_heaps = (*peb).number_of_heaps as usize;

    for i in 0..number_of_heaps {
        let heap = *process_heaps.add(i);
        if !heap.is_null() {
            let instance = &mut *(heap as *mut Instance);
            if instance.magic == INSTANCE_MAGIC {
                return Some(instance); // Return the instance if the magic value matches
            }
        }
    }
    None
}
