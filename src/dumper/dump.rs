use core::ffi::c_void;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    common::utils::dbj2_hash,
    debug_println,
    instance::get_instance,
    native::{
        memory::{query_memory_info, read_memory, read_remote_int_ptr, read_remote_wstr},
        ntdef::{ProcessBasicInformation, MEM_COMMIT, PAGE_NOACCESS},
    },
};

use super::mdfile::{MemoryRegion, ModuleInfo};

/// Retrieves the list of loaded modules in a process's memory.
///
/// Uses the process handle to query the PEB (Process Environment Block) and retrieves
/// information about the loaded modules in the process. Optionally filters modules by a hash.
pub fn get_modules_info(process_handle: *mut c_void, module_hash: Option<u32>) -> Vec<ModuleInfo> {
    let mut process_information: ProcessBasicInformation = unsafe { core::mem::zeroed() };
    let mut return_length: u32 = 0;

    // Query the process information to get the PEB base address.
    let status = unsafe {
        get_instance()
            .unwrap()
            .ntdll
            .nt_query_information_process
            .run(
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
        "[+] PEB Base Address: ",
        process_information.peb_base_address as usize,
        true
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
                "[-] Failed to query memory at address: ",
                memory_address as usize,
                true
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
