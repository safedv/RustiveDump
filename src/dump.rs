#[cfg(feature = "verbose")]
use libc_print::libc_println;

use core::ffi::c_void;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    debug_println,
    mdfile::{MemoryRegion, ModuleInfo},
    ntapi::{
        def::{MEM_COMMIT, PAGE_NOACCESS},
        memory::{query_memory_info, read_memory},
    },
};

/// Traverses and dumps the memory regions of a process, storing the memory regions and the memory dump.
///
/// This function iterates through the memory space of a process, queries memory information,
/// reads the memory, and dumps it into the provided vectors.
pub unsafe fn dump_memory_regions(
    process_handle: *mut c_void,
    module_info_list: &mut Vec<ModuleInfo>,
    memory64list: &mut Vec<MemoryRegion>,
    memory_regions: &mut Vec<u8>,
) {
    // Initialize variables for memory region traversal and dumping.
    let mut memory_address: usize = 0; // Start memory address for dumping.
    let max_memory_address: usize = 0x7FFF_FFFE_FFFF; // The maximum user-mode address.
    let mut tmp_module_base_name = String::new(); // Auxiliary variable to store the module's base name.
    let mut tmp_memory_region_size = 0usize; // To track the size of the memory regions.

    // Loop through the process's memory space until the maximum address is reached.
    while memory_address < max_memory_address {
        // Query information about the current memory region.
        if let Some(memory_info) = query_memory_info(process_handle, memory_address as *mut c_void)
        {
            // Check if the memory region is committed and accessible.
            if memory_info.protect != PAGE_NOACCESS && memory_info.state == MEM_COMMIT {
                // Try to match the current region with known modules based on their base addresses.
                let matching_object = module_info_list
                    .iter_mut()
                    .find(|obj| obj.base_name == tmp_module_base_name);

                // If the region size is 0x1000 and does not match a module, update the module info.
                if memory_info.region_size == 0x1000
                    && memory_info.base_address as usize
                        != matching_object
                            .as_ref()
                            .map(|obj| obj.base_address)
                            .unwrap_or(0)
                {
                    // If a module was found, update its region size.
                    if let Some(module) = matching_object {
                        module.region_size = tmp_memory_region_size;
                    }

                    // Update auxiliary name and size based on the current memory region.
                    tmp_module_base_name = module_info_list
                        .iter()
                        .find(|module| module.base_address == memory_info.base_address as usize)
                        .map(|module| module.base_name.clone())
                        .unwrap_or_else(|| "Unknown".to_string());
                    tmp_memory_region_size = memory_info.region_size as usize;
                } else {
                    // Accumulate the region size.
                    tmp_memory_region_size += memory_info.region_size as usize;
                }

                // Read the memory region if it's valid and dump it.
                if let Some(buffer) = read_memory(
                    process_handle as *mut c_void,
                    memory_info.base_address as *mut c_void,
                    memory_info.region_size as usize,
                ) {
                    // Append the read memory region to the dump.
                    memory_regions.extend_from_slice(&buffer);
                    // Add the memory region to the list of dumped regions.
                    memory64list.push(MemoryRegion {
                        base_address: memory_address,
                        region_size: memory_info.region_size as usize,
                    });
                }
            }

            // Move to the next memory region by incrementing the memory address.
            memory_address += memory_info.region_size as usize;
        } else {
            // If querying the memory fails, print an error message and break out of the loop.
            debug_println!(
                "[-] Failed to query memory at address: 0x{:X}",
                memory_address
            );
            break;
        }
    }

    // Update the region size of the last matched module.
    if let Some(module) = module_info_list
        .iter_mut()
        .find(|module| module.base_name == tmp_module_base_name)
    {
        module.region_size = tmp_memory_region_size;
    }
}
