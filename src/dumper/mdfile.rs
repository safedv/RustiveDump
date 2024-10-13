use alloc::{string::String, vec::Vec};

use crate::{debug_println, native::ntdef::OSVersionInfo};

// Struct for holding information about a module (DLL), including its base name,
// full path, base address in memory, and the size of the memory region it occupies.
pub struct ModuleInfo {
    pub base_name: String,
    pub full_dll_name: String,
    pub base_address: usize,
    pub region_size: usize,
}

// Struct to represent a memory region, storing the base address and region size.
pub struct MemoryRegion {
    pub base_address: usize,
    pub region_size: usize,
}

// Function that generates a memory dump file in a custom format.
// It takes the OS version, list of module information, memory regions, and memory dump data as input.
pub fn generate_memory_dump_file(
    os_version: OSVersionInfo,
    module_info_list: Vec<ModuleInfo>,
    memory64list: Vec<MemoryRegion>,
    regions_memdump: Vec<u8>,
) -> Vec<u8> {
    // Calculate the size of the ModuleList stream.
    let number_modules = module_info_list.len();
    let mut modulelist_size = 4; // Starts with 4 bytes for the number of modules.
    modulelist_size += 108 * number_modules; // Each module takes 108 bytes for basic information.

    // Add the size of the full path names for each module.
    for module in &module_info_list {
        let module_fullpath_len = module.full_dll_name.len();
        modulelist_size += (module_fullpath_len * 2) + 8; // Each path is encoded in UTF-16 (2 bytes per character).
    }

    // Calculate the offset and size for the Memory64List stream.
    let mem64list_offset = modulelist_size + 0x7c; // 0x7c is a constant offset before the ModuleList stream starts.
    let mem64list_size = 16 + 16 * memory64list.len(); // Memory64List contains 16 bytes per memory region entry.
    let offset_memory_regions = mem64list_offset + mem64list_size; // The actual memory dump data comes after Memory64List.

    // Debug prints to show calculated values if verbose mode is enabled.
    debug_println!("[+] Total number of modules: ", number_modules, false);
    debug_println!("[+] ModuleListStream size: ", modulelist_size, false);
    debug_println!("[+] Mem64List offset: ", mem64list_offset, false);
    debug_println!("[+] Mem64List size: ", mem64list_size, false);
    debug_println!(
        "[+] Regions memory dump size: ",
        regions_memdump.len(),
        false
    );
    debug_println!("[+] Number of memory regions: ", memory64list.len(), false);

    // **Header section for the dump file**
    let mut header: Vec<u8> = Vec::new();
    header.extend(b"MDMP"); // Add the signature "MDMP".
    header.extend(&[0x93, 0xa7]); // Version information.
    header.extend(&[0x00, 0x00]);
    header.extend(&[0x03, 0x00, 0x00, 0x00]); // Header size.
    header.extend(&[0x20, 0x00, 0x00, 0x00]); // Reserved space in the header.
    let mut new_vec = Vec::new();
    new_vec.resize(32 - header.len(), 0); // Pad the header to 32 bytes.
    header.extend(&new_vec);

    // **Stream Directory**: Specifies the types and offsets of the data streams (ModuleList, Memory64List, etc.).
    let mut stream_directory: Vec<u8> = Vec::new();
    stream_directory.extend(&[0x04, 0x00, 0x00, 0x00]); // Type of stream: ModuleList.
    stream_directory.extend(&(modulelist_size as u32).to_le_bytes()); // ModuleList size.
    stream_directory.extend(&[0x7c, 0x00, 0x00, 0x00]); // ModuleList offset.

    stream_directory.extend(&[0x07, 0x00, 0x00, 0x00]); // Type of stream: SystemInfo.
    stream_directory.extend(&[0x38, 0x00, 0x00, 0x00]); // Size of SystemInfo stream.
    stream_directory.extend(&[0x44, 0x00, 0x00, 0x00]); // Offset of SystemInfo stream.

    stream_directory.extend(&[0x09, 0x00, 0x00, 0x00]); // Type of stream: Memory64List.
    stream_directory.extend(&(mem64list_size as u32).to_le_bytes()); // Memory64List size.
    stream_directory.extend(&(mem64list_offset as u32).to_le_bytes()); // Memory64List offset.

    // **SystemInfo stream**: Contains basic information about the OS version.
    let major_version = os_version.dw_major_version;
    let minor_version = os_version.dw_minor_version;
    let build_number = os_version.dw_build_number;
    let platform_id = os_version.dw_platform_id;
    let csd_version = " ".encode_utf16().collect::<Vec<u16>>(); // CSDVersion is encoded in UTF-16.

    let mut systeminfo_stream: Vec<u8> = Vec::new();
    systeminfo_stream.extend(&9u16.to_le_bytes()); // Processor architecture.
    let mut new_vec = Vec::new();
    new_vec.resize(6, 0); // Padding.
    systeminfo_stream.extend(&new_vec);
    systeminfo_stream.extend(&major_version.to_le_bytes()); // OS major version.
    systeminfo_stream.extend(&minor_version.to_le_bytes()); // OS minor version.
    systeminfo_stream.extend(&build_number.to_le_bytes()); // OS build number.
    systeminfo_stream.extend(&platform_id.to_le_bytes()); // Platform ID.
    for word in csd_version {
        systeminfo_stream.extend(&word.to_le_bytes()); // CSDVersion string.
    }
    let mut new_vec = Vec::new();
    new_vec.resize(56 - systeminfo_stream.len(), 0); // Padding to 56 bytes.
    systeminfo_stream.extend(&new_vec);

    // **ModuleListStream**: Contains details of all modules (DLLs) loaded in the process.
    let mut modulelist_stream = Vec::new();
    modulelist_stream.extend(&(number_modules as u32).to_le_bytes()); // Number of modules.

    // Pointer to the location of the full module paths in the file.
    let mut pointer_index: u64 =
        0x7c + modulelist_stream.len() as u64 + (108 * number_modules) as u64;

    // For each module, add its base address, region size, and path pointer.
    for module in &module_info_list {
        modulelist_stream.extend(&(module.base_address as u64).to_le_bytes());
        modulelist_stream.extend(&(module.region_size as u64).to_le_bytes());
        modulelist_stream.extend(&[0; 4]); // Padding.
        modulelist_stream.extend(&pointer_index.to_le_bytes()); // Pointer to the module's full path.

        pointer_index += ((module.full_dll_name.len() * 2) + 8) as u64; // Update pointer for the next module's path.
        let mut new_vec = Vec::new();
        new_vec.resize(108 - (8 + 8 + 4 + 8), 0); // Padding to 108 bytes per module entry.
        modulelist_stream.extend(&new_vec);
    }

    // Add the full path names for each module, encoded in UTF-16.
    for module in &module_info_list {
        let unicode_bytearr: Vec<u8> = module
            .full_dll_name
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        modulelist_stream.extend(&((module.full_dll_name.len() * 2) as u32).to_le_bytes()); // Path length.
        modulelist_stream.extend(unicode_bytearr.clone()); // Encoded path.
        let mut new_vec = Vec::new();
        new_vec.resize(4, 0); // Padding.
        modulelist_stream.extend(&new_vec);
    }

    // **Memory64ListStream**: Contains memory region information.
    let mut memory64list_stream: Vec<u8> = Vec::new();
    memory64list_stream.extend(&(memory64list.len() as u64).to_le_bytes()); // Number of memory regions.
    memory64list_stream.extend(&(offset_memory_regions as u64).to_le_bytes()); // Offset to memory dump data.
    for mem64 in &memory64list {
        memory64list_stream.extend(&(mem64.base_address as u64).to_le_bytes()); // Memory region base address.
        memory64list_stream.extend(&(mem64.region_size as u64).to_le_bytes()); // Memory region size.
    }

    // **Final dump file**: Concatenate all sections to create the final memory dump file.
    let mut dump_file = Vec::new();
    dump_file.extend(header); // Add header.
    dump_file.extend(stream_directory); // Add stream directory.
    dump_file.extend(systeminfo_stream); // Add system info stream.
    dump_file.extend(modulelist_stream); // Add module list stream.
    dump_file.extend(memory64list_stream); // Add memory64 list stream.
    dump_file.extend(regions_memdump); // Add raw memory dump.

    dump_file // Return the final memory dump file as a byte vector.
}
