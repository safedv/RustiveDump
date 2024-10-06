use core::{
    arch::asm,
    ffi::{c_long, c_ulong, c_void},
    ptr,
};

use crate::common::utils::string_length_w;

pub const PROCESS_QUERY_INFORMATION: AccessMask = 0x0400;
pub const PROCESS_VM_READ: AccessMask = 0x0010;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

// Definition of LIST_ENTRY
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

// Definition of UNICODE_STRING
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl UnicodeString {
    pub fn new() -> Self {
        UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        }
    }

    // RtlInitUnicodeString
    pub fn init(&mut self, source_string: *const u16) {
        if !source_string.is_null() {
            let dest_size = string_length_w(source_string) * 2;
            self.length = dest_size as u16;
            self.maximum_length = (dest_size + 2) as u16;
            self.buffer = source_string as *mut u16;
        } else {
            self.length = 0;
            self.maximum_length = 0;
            self.buffer = ptr::null_mut();
        }
    }
}

pub type ULONG = c_ulong;
pub type HANDLE = *mut c_void;
pub type AccessMask = ULONG;

#[repr(C)]
pub struct ObjectAttributes {
    pub length: ULONG,
    pub root_directory: HANDLE,
    pub object_name: *mut UnicodeString,
    pub attributes: ULONG,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

impl ObjectAttributes {
    pub fn new() -> Self {
        ObjectAttributes {
            length: 0,
            root_directory: ptr::null_mut(),
            object_name: ptr::null_mut(),
            attributes: 0,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        }
    }

    //InitializeObjectAttributes
    pub fn initialize(
        p: &mut ObjectAttributes,
        n: *mut UnicodeString,
        a: ULONG,
        r: HANDLE,
        s: *mut c_void,
    ) {
        p.length = core::mem::size_of::<ObjectAttributes>() as ULONG;
        p.root_directory = r;
        p.attributes = a;
        p.object_name = n;
        p.security_descriptor = s;
        p.security_quality_of_service = ptr::null_mut();
    }
}

#[repr(C)]
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: u32,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub r#type: u32,
}

#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    pub peb_base_address: *mut c_void,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: *mut c_void,
    pub inherited_from_unique_process_id: *mut c_void,
}

pub const MEM_COMMIT: u32 = 0x1000;
pub const PAGE_NOACCESS: u32 = 0x01;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LargeInteger {
    pub low_part: u32,
    pub high_part: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SectionPointer {
    pub section_pointer: *mut c_void,
    pub check_sum: c_ulong,
}

#[repr(C)]
pub union HashLinksOrSectionPointer {
    pub hash_links: ListEntry,
    pub section_pointer: SectionPointer,
}

#[repr(C)]
pub union TimeDateStampOrLoadedImports {
    pub time_date_stamp: c_ulong,
    pub loaded_imports: *mut c_void,
}

#[repr(C)]
pub struct LoaderDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: c_ulong,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: c_ulong,
    pub load_count: i16,
    pub tls_index: i16,
    pub hash_links_or_section_pointer: HashLinksOrSectionPointer,
    pub time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports,
    pub entry_point_activation_context: *mut c_void,
    pub patch_information: *mut c_void,
    pub forwarder_links: ListEntry,
    pub service_tag_links: ListEntry,
    pub static_links: ListEntry,
}

#[repr(C)]
pub struct PebLoaderData {
    pub length: c_ulong,
    pub initialized: c_ulong,
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: bool,
    pub read_image_file_exec_options: bool,
    pub being_debugged: bool,
    pub spare: bool,
    pub mutant: *mut c_void,
    pub image_base: *mut c_void,
    pub loader_data: *const PebLoaderData,
    pub process_parameters: *const RtlUserProcessParameters,
    pub sub_system_data: *mut c_void,
    pub process_heap: *mut c_void,
    pub fast_peb_lock: *mut c_void,
    pub fast_peb_lock_routine: *mut c_void,
    pub fast_peb_unlock_routine: *mut c_void,
    pub environment_update_count: c_ulong,
    pub kernel_callback_table: *const *mut c_void,
    pub event_log_section: *mut c_void,
    pub event_log: *mut c_void,
    pub free_list: *mut c_void,
    pub tls_expansion_counter: c_ulong,
    pub tls_bitmap: *mut c_void,
    pub tls_bitmap_bits: [c_ulong; 2],
    pub read_only_shared_memory_base: *mut c_void,
    pub read_only_shared_memory_heap: *mut c_void,
    pub read_only_static_server_data: *const *mut c_void,
    pub ansi_code_page_data: *mut c_void,
    pub oem_code_page_data: *mut c_void,
    pub unicode_case_table_data: *mut c_void,
    pub number_of_processors: c_ulong,
    pub nt_global_flag: c_ulong,
    pub spare_2: [u8; 4],
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: c_ulong,
    pub heap_segment_commit: c_ulong,
    pub heap_de_commit_total_free_threshold: c_ulong,
    pub heap_de_commit_free_block_threshold: c_ulong,
    pub number_of_heaps: c_ulong,
    pub maximum_number_of_heaps: c_ulong,
    pub process_heaps: *const *const *mut c_void,
    pub gdi_shared_handle_table: *mut c_void,
    pub process_starter_helper: *mut c_void,
    pub gdi_dc_attribute_list: *mut c_void,
    pub loader_lock: *mut c_void,
    pub os_major_version: c_ulong,
    pub os_minor_version: c_ulong,
    pub os_build_number: c_ulong,
    pub os_platform_id: c_ulong,
    pub image_sub_system: c_ulong,
    pub image_sub_system_major_version: c_ulong,
    pub image_sub_system_minor_version: c_ulong,
    pub gdi_handle_buffer: [c_ulong; 22],
    pub post_process_init_routine: c_ulong,
    pub tls_expansion_bitmap: c_ulong,
    pub tls_expansion_bitmap_bits: [u8; 80],
    pub session_id: c_ulong,
}

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,
    pub flags: u32,
    pub debug_flags: u32,
    pub console_handle: *mut c_void,
    pub console_flags: u32,
    pub standard_input: *mut c_void,
    pub standard_output: *mut c_void,
    pub standard_error: *mut c_void,
    pub current_directory_path: UnicodeString,
    pub current_directory_handle: *mut c_void,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: *mut c_void,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,
    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UnicodeString,
    pub desktop_info: UnicodeString,
    pub shell_info: UnicodeString,
    pub runtime_data: UnicodeString,
    pub current_directories: [UnicodeString; 32],
    pub environment_size: u32,
    pub environment_version: u32,
    pub package_dependency_data: *mut c_void,
    pub process_group_id: u32,
    pub loader_threads: u32,
}

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ImageNtHeaders {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[cfg(target_arch = "x86_64")]
pub fn find_peb() -> *mut PEB {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb_ptr
        );
    }
    peb_ptr
}

#[repr(C)]
pub struct OSVersionInfo {
    pub dw_os_version_info_size: u32,
    pub dw_major_version: u32,
    pub dw_minor_version: u32,
    pub dw_build_number: u32,
    pub dw_platform_id: u32,
    pub sz_csd_version: [u16; 128], // WCHAR is usually represented as u16 in Rust
    pub dw_os_version_info_size_2: u32,
    pub dw_major_version_2: u32,
    pub dw_minor_version_2: u32,
    pub dw_build_number_2: u32,
    pub dw_platform_id_2: u32,
}

impl OSVersionInfo {
    pub fn new() -> Self {
        OSVersionInfo {
            dw_os_version_info_size: core::mem::size_of::<OSVersionInfo>() as u32,
            dw_major_version: 0,
            dw_minor_version: 0,
            dw_build_number: 0,
            dw_platform_id: 0,
            sz_csd_version: [0; 128],
            dw_os_version_info_size_2: core::mem::size_of::<OSVersionInfo>() as u32,
            dw_major_version_2: 0,
            dw_minor_version_2: 0,
            dw_build_number_2: 0,
            dw_platform_id_2: 0,
        }
    }
}
#[allow(dead_code)]
#[repr(C)]
pub union IO_STATUS_BLOCK_u {
    pub status: i32,
    pub pointer: *mut c_void,
}

#[allow(dead_code)]
#[repr(C)]
pub struct IoStatusBlock {
    pub u: IO_STATUS_BLOCK_u,
    pub information: u32,
}

#[repr(C)]
pub struct LUID {
    pub low_part: u32,
    pub high_part: i32,
}

#[repr(C)]
pub struct TokenPrivileges {
    pub privilege_count: u32,
    pub luid: LUID,
    pub attributes: u32,
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: LargeInteger,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: LargeInteger,
    pub user_time: LargeInteger,
    pub kernel_time: LargeInteger,
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: *mut c_void,
    pub inherited_from_unique_process_id: *mut c_void,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
    pub read_operation_count: LargeInteger,
    pub write_operation_count: LargeInteger,
    pub other_operation_count: LargeInteger,
    pub read_transfer_count: LargeInteger,
    pub write_transfer_count: LargeInteger,
    pub other_transfer_count: LargeInteger,
    pub threads: [SystemThreadInformation; 1],
}

#[repr(C)]
pub struct SystemThreadInformation {
    pub kernel_time: LargeInteger,
    pub user_time: LargeInteger,
    pub create_time: LargeInteger,
    pub wait_time: u32,
    pub start_address: *mut c_void,
    pub client_id: ClientId,
    pub priority: c_long,
    pub base_priority: c_long,
    pub context_switches: u32,
    pub thread_state: u32,
    pub wait_reason: u32,
}

#[repr(C)]
pub struct ClientId {
    pub unique_process: *mut c_void,
    pub unique_thread: *mut c_void,
}

impl ClientId {
    pub fn new() -> Self {
        ClientId {
            unique_process: core::ptr::null_mut(),
            unique_thread: core::ptr::null_mut(),
        }
    }
}

pub const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;
