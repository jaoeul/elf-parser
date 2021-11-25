use std::convert::TryInto;

const OFFSET_MAGIC:                          usize = 0;
const OFFSET_MAJOR_LINKER_VERSION:           usize = 2;
const OFFSET_MINOR_LINKER_VERSION:           usize = 3;
const OFFSET_SIZE_OF_CODE:                   usize = 4;
const OFFSET_SIZE_OF_INITIALIZED_DATA:       usize = 8;
const OFFSET_SIZE_OF_UNINITIALIZED_DATA:     usize = 12;
const OFFSET_ADDRESS_OF_ENTRY_POINT:         usize = 16;
const OFFSET_BASE_OF_CODE:                   usize = 20;

const OFFSET_BASE_OF_DATA_32:                usize = 24;
const OFFSET_IMAGE_BASE_32:                  usize = 28;

const OFFSET_IMAGE_BASE_64:                  usize = 24;

const OFFSET_SECTION_ALIGNMENT:              usize = 32;
const OFFSET_FILE_ALIGNMENT:                 usize = 36;
const OFFSET_MAJOR_OPERATING_SYSTEM_VERSION: usize = 40;
const OFFSET_MINOR_OPERATING_SYSTEM_VERSION: usize = 42;
const OFFSET_MAJOR_IMAGE_VERSION:            usize = 44;
const OFFSET_MINOR_IMAGE_VERSION:            usize = 46;
const OFFSET_MAJOR_SUBSYSTEM_VERSION:        usize = 48;
const OFFSET_MINOR_SUBSYSTEM_VERSION:        usize = 50;
const OFFSET_WIN32_VERSION_VALUE:            usize = 52;
const OFFSET_SIZE_OF_IMAGE:                  usize = 56;
const OFFSET_SIZE_OF_HEADERS:                usize = 60;
const OFFSET_CHECKSUM:                       usize = 64;
const OFFSET_SUBSYSTEM:                      usize = 68;
const OFFSET_DLL_CHARACTERISTICS:            usize = 70;
const OFFSET_SIZE_OF_STACK_RESERVE:          usize = 72;

const OFFSET_SIZE_OF_STACK_COMMIT_32:        usize = 76;
const OFFSET_SIZE_OF_HEAP_RESERVE_32:        usize = 80;
const OFFSET_SIZE_OF_HEAP_COMMIT_32:         usize = 84;
const OFFSET_LOADER_FLAGS_32:                usize = 88;
const OFFSET_NUMBER_OF_RVA_AND_SIZES_32:     usize = 92;

const OFFSET_EXPORT_TABLE_32:                usize = 96;
const OFFSET_IMPORT_TABLE_32:                usize = 104;
const OFFSET_RESOURCE_TABLE_32:              usize = 112;
const OFFSET_EXCEPTION_TABLE_32:             usize = 120;
const OFFSET_CERTIFICATE_TABLE_32:           usize = 128;
const OFFSET_BASE_RELOCATION_TABLE_32:       usize = 136;
const OFFSET_DEBUG_32:                       usize = 144;
const OFFSET_ARCHITECTURE_32:                usize = 152;
const OFFSET_GLOBAL_PTR_32:                  usize = 160;
const OFFSET_TLS_TABLE_32:                   usize = 168;
const OFFSET_LOAD_CONFIG_TABLE_32:           usize = 176;
const OFFSET_BOUND_IMPORT_32:                usize = 184;
const OFFSET_IAT_32:                         usize = 192;
const OFFSET_DELAY_IMPORT_DESCRIPTOR_32:     usize = 200;
const OFFSET_CLR_RUNTIME_HEADER_32:          usize = 208;

const OFFSET_SIZE_OF_STACK_COMMIT_64:        usize = 80;
const OFFSET_SIZE_OF_HEAP_RESERVE_64:        usize = 88;
const OFFSET_SIZE_OF_HEAP_COMMIT_64:         usize = 96;
const OFFSET_LOADER_FLAGS_64:                usize = 104;
const OFFSET_NUMBER_OF_RVA_AND_SIZES_64:     usize = 108;

const OFFSET_EXPORT_TABLE_64:                usize = 112;
const OFFSET_IMPORT_TABLE_64:                usize = 120;
const OFFSET_RESOURCE_TABLE_64:              usize = 128;
const OFFSET_EXCEPTION_TABLE_64:             usize = 136;
const OFFSET_CERTIFICATE_TABLE_64:           usize = 144;
const OFFSET_BASE_RELOCATION_TABLE_64:       usize = 152;
const OFFSET_DEBUG_64:                       usize = 160;
const OFFSET_ARCHITECTURE_64:                usize = 168;
const OFFSET_GLOBAL_PTR_64:                  usize = 176;
const OFFSET_TLS_TABLE_64:                   usize = 184;
const OFFSET_LOAD_CONFIG_TABLE_64:           usize = 192;
const OFFSET_BOUND_IMPORT_64:                usize = 200;
const OFFSET_IAT_64:                         usize = 208;
const OFFSET_DELAY_IMPORT_DESCRIPTOR_64:     usize = 216;
const OFFSET_CLR_RUNTIME_HEADER_64:          usize = 224;

const MAGIC_PE32:    u16 = 0x10b;
const MAGIC_PE64:    u16 = 0x20b;
const MAGIC_UNKNOWN: u16 = 0xFFFF;

#[derive(Debug)]
pub struct OptionalHeader {
    // The unsigned integer that identifies the state of the image file. The
    // most common number is 0x10B, which identifies it as a normal executable
    // file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a
    // PE32+ executable.
    pub magic: u16,

    // The linker major version number.
    pub major_linker_version: u8,

    // The linker minor version number.
    pub minor_linker_version: u8,

    // The size of the code (text) section, or the sum of all code sections if
    // there are multiple sections.
    pub size_of_code: u32,

    // The size of the initialized data section, or the sum of all such sections
    // if there are multiple data sections.
    pub size_of_initialized_data: u32,

    // The size of the uninitialized data section (BSS), or the sum of all such
    // sections if there are multiple BSS sections.
    pub size_of_uninitialized_data: u32,

    // The address of the entry point relative to the image base when the
    // executable file is loaded into memory. For program images, this is the
    // starting address. For device drivers, this is the address of the
    // initialization function. An entry point is optional for DLLs. When no
    // entry point is present, this field must be zero.
    pub address_of_entry_point: u32,

    // The address that is relative to the image base of the beginning-of-code
    // section when it is loaded into memory.
    pub base_of_code: u32,

    // The address that is relative to the image base of the beginning-of-data
    // section when it is loaded into memory. Only present in PE32 binaries.
    pub base_of_data: u32,

    // The preferred address of the first byte of image when loaded into memory;
    // must be a multiple of 64 K. The default for DLLs is 0x10000000. The
    // default for Windows CE EXEs is 0x00010000. The default for Windows NT,
    // Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is
    // 0x00400000.
    pub image_base: u64,

    // The alignment (in bytes) of sections when they are loaded into memory. It
    // must be greater than or equal to FileAlignment. The default is the page
    // size for the architecture.
    pub section_alignment: u32,

    // The alignment factor (in bytes) that is used to align the raw data of
    // sections in the image file. The value should be a power of 2 between 512
    // and 64 K, inclusive. The default is 512. If the SectionAlignment is less
    // than the architecture's page size, then FileAlignment must match
    // SectionAlignment.
    pub file_alignment: u32,

    // The major version number of the required operating system.
    pub major_operating_system_version: u16,

    // The minor version number of the required operating system.
    pub minor_operating_system_version: u16,

    // The major version number of the image.
    pub major_image_version: u16,

    // The minor version number of the image.
    pub minor_image_version: u16,

    // The major version number of the subsystem.
    pub major_subsystem_version: u16,

    // The minor version number of the subsystem.
    pub minor_subsystem_version: u16,

    // Reserved, must be zero.
    pub win32_version_value: u32,

    // The size (in bytes) of the image, including all headers, as the image is
    // loaded in memory. It must be a multiple of SectionAlignment.
    pub size_of_image: u32,

    // The combined size of an MS-DOS stub, PE header, and section headers
    // rounded up to a multiple of FileAlignment.
    pub size_of_headers: u32,

    // The image file checksum. The algorithm for computing the checksum is
    // incorporated into IMAGHELP.DLL. The following are checked for validation
    // at load time: all drivers, any DLL loaded at boot time, and any DLL that
    // is loaded into a critical Windows process.
    pub checksum: u32,

    // The subsystem that is required to run this image. For more information,
    // see Windows Subsystem.
    pub subsystem: u16,

    // For more information, see DLL Characteristics later in this
    // specification.
    pub dll_characteristics: u16,

    // The size of the stack to reserve. Only SizeOfStackCommit is committed;
    // the rest is made available one page at a time until the reserve size is
    // reached.
    pub size_of_stack_reserve: u64,

    // The size of the stack to commit.
    pub size_of_stack_commit: u64,

    // The size of the local heap space to reserve. Only SizeOfHeapCommit is
    // committed; the rest is made available one page at a time until the
    // reserve size is reached.
    pub size_of_heap_reserve: u64,

    // The size of the local heap space to commit.
    pub size_of_heap_commit: u64,

    // Reserved, must be zero.
    pub loader_flags: u32,

    // The number of data-directory entries in the remainder of the optional
    // header. Each describes a location and size.
    pub number_of_rva_and_sizes: u32,

    // The export table address and size. For more information see .edata
    // Section (Image Only).
    pub export_table: u64,

    // The import table address and size. For more information, see The .idata
    // Section.
    pub import_table: u64,

    // The resource table address and size. For more information, see The .rsrc
    // Section.
    pub resource_table: u64,

    // The exception table address and size. For more information, see The
    // .pdata Section.
    pub exception_table: u64,

    // The attribute certificate table address and size. For more information,
    // see The Attribute Certificate Table (Image Only).
    pub certificate_table: u64,

    // The base relocation table address and size. For more information, see The
    // .reloc Section (Image Only).
    pub base_relocation_table: u64,

    // The debug data starting address and size. For more information, see The
    // .debug Section.
    pub debug: u64,

    // Reserved, must be 0
    pub architecture: u64,

    // The RVA of the value to be stored in the global pointer register. The
    // size member of this structure must be set to zero.
    pub global_ptr: u64,

    // The thread local storage (TLS) table address and size. For more
    // information, see The .tls Section.
    pub tls_table: u64,

    // The load configuration table address and size. For more information, see
    // The Load Configuration Structure (Image Only).
    pub load_config_table: u64,

    // The bound import table address and size.
    pub bound_import: u64,

    // The import address table address and size. For more information, see
    // Import Address Table.
    pub iat: u64,

    // The delay import descriptor address and size. For more information, see
    // Delay-Load Import Tables (Image Only).
    pub delay_import_descriptor: u64,

    // The CLR runtime header address and size. For more information, see The
    // .cormeta Section (Object Only).
    pub clr_runtime_header: u64,
}

impl OptionalHeader {
    pub fn new(opt_bytes: &[u8]) -> OptionalHeader {
        let magic = u16::from_le_bytes(opt_bytes[OFFSET_MAGIC..OFFSET_MAGIC + 2].try_into().expect("Slice is of incorrect length"));
        if magic == MAGIC_PE32 {
            OptionalHeader {
                magic:                          u16::from_le_bytes(opt_bytes[OFFSET_MAGIC..OFFSET_MAGIC + 2].try_into().expect("Slice is of incorrect length")),
                major_linker_version:           u8::from_le_bytes(opt_bytes[OFFSET_MAJOR_LINKER_VERSION..OFFSET_MAJOR_LINKER_VERSION + 1].try_into().expect("Slice is of incorrect length")),
                minor_linker_version:           u8::from_le_bytes(opt_bytes[OFFSET_MINOR_LINKER_VERSION..OFFSET_MINOR_LINKER_VERSION + 1].try_into().expect("Slice is of incorrect length")),
                size_of_code:                   u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_CODE..OFFSET_SIZE_OF_CODE + 4].try_into().expect("Slice is of incorrect length")),
                size_of_initialized_data:       u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_INITIALIZED_DATA..OFFSET_SIZE_OF_INITIALIZED_DATA + 4].try_into().expect("Slice is of incorrect length")),
                size_of_uninitialized_data:     u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_UNINITIALIZED_DATA..OFFSET_SIZE_OF_UNINITIALIZED_DATA + 4].try_into().expect("Slice is of incorrect length")),
                address_of_entry_point:         u32::from_le_bytes(opt_bytes[OFFSET_ADDRESS_OF_ENTRY_POINT..OFFSET_ADDRESS_OF_ENTRY_POINT + 4].try_into().expect("Slice is of incorrect length")),
                base_of_code:                   u32::from_le_bytes(opt_bytes[OFFSET_BASE_OF_CODE..OFFSET_BASE_OF_CODE + 4].try_into().expect("Slice is of incorrect length")),
                base_of_data:                   u32::from_le_bytes(opt_bytes[OFFSET_BASE_OF_DATA_32..OFFSET_BASE_OF_DATA_32 + 4].try_into().expect("Slice is of incorrect length")),
                image_base:                     u64::from_le_bytes(opt_bytes[OFFSET_IMAGE_BASE_32..OFFSET_IMAGE_BASE_32 + 8].try_into().expect("Slice is of incorrect length")),
                section_alignment:              u32::from_le_bytes(opt_bytes[OFFSET_SECTION_ALIGNMENT..OFFSET_SECTION_ALIGNMENT + 4].try_into().expect("Slice is of incorrect length")),
                file_alignment:                 u32::from_le_bytes(opt_bytes[OFFSET_FILE_ALIGNMENT..OFFSET_FILE_ALIGNMENT + 4].try_into().expect("Slice is of incorrect length")),
                major_operating_system_version: u16::from_le_bytes(opt_bytes[OFFSET_MAJOR_OPERATING_SYSTEM_VERSION..OFFSET_MAJOR_OPERATING_SYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                minor_operating_system_version: u16::from_le_bytes(opt_bytes[OFFSET_MINOR_OPERATING_SYSTEM_VERSION..OFFSET_MINOR_OPERATING_SYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                major_image_version:            u16::from_le_bytes(opt_bytes[OFFSET_MAJOR_IMAGE_VERSION..OFFSET_MAJOR_IMAGE_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                minor_image_version:            u16::from_le_bytes(opt_bytes[OFFSET_MINOR_IMAGE_VERSION..OFFSET_MINOR_IMAGE_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                major_subsystem_version:        u16::from_le_bytes(opt_bytes[OFFSET_MAJOR_SUBSYSTEM_VERSION..OFFSET_MAJOR_SUBSYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                minor_subsystem_version:        u16::from_le_bytes(opt_bytes[OFFSET_MINOR_SUBSYSTEM_VERSION..OFFSET_MINOR_SUBSYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                win32_version_value:            u32::from_le_bytes(opt_bytes[OFFSET_WIN32_VERSION_VALUE..OFFSET_WIN32_VERSION_VALUE + 4].try_into().expect("Slice is of incorrect length")),
                size_of_image:                  u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_IMAGE..OFFSET_SIZE_OF_IMAGE + 4].try_into().expect("Slice is of incorrect length")),
                size_of_headers:                u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_HEADERS..OFFSET_SIZE_OF_HEADERS + 4].try_into().expect("Slice is of incorrect length")),
                checksum:                       u32::from_le_bytes(opt_bytes[OFFSET_CHECKSUM..OFFSET_CHECKSUM + 4].try_into().expect("Slice is of incorrect length")),
                subsystem:                      u16::from_le_bytes(opt_bytes[OFFSET_SUBSYSTEM..OFFSET_SUBSYSTEM + 2].try_into().expect("Slice is of incorrect length")),
                dll_characteristics:            u16::from_le_bytes(opt_bytes[OFFSET_DLL_CHARACTERISTICS..OFFSET_DLL_CHARACTERISTICS + 2].try_into().expect("Slice is of incorrect length")),
                size_of_stack_reserve:          u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_STACK_RESERVE..OFFSET_SIZE_OF_STACK_RESERVE + 8].try_into().expect("Slice is of incorrect length")),
                size_of_stack_commit:           u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_STACK_COMMIT_32..OFFSET_SIZE_OF_STACK_COMMIT_32 + 8].try_into().expect("Slice is of incorrect length")),
                size_of_heap_reserve:           u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_HEAP_RESERVE_32..OFFSET_SIZE_OF_HEAP_RESERVE_32 + 8].try_into().expect("Slice is of incorrect length")),
                size_of_heap_commit:            u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_HEAP_COMMIT_32..OFFSET_SIZE_OF_HEAP_COMMIT_32 + 8].try_into().expect("Slice is of incorrect length")),
                loader_flags:                   u32::from_le_bytes(opt_bytes[OFFSET_LOADER_FLAGS_32..OFFSET_LOADER_FLAGS_32 + 4].try_into().expect("Slice is of incorrect length")),
                number_of_rva_and_sizes:        u32::from_le_bytes(opt_bytes[OFFSET_NUMBER_OF_RVA_AND_SIZES_32..OFFSET_NUMBER_OF_RVA_AND_SIZES_32 + 4].try_into().expect("Slice is of incorrect length")),
                export_table:                   u64::from_le_bytes(opt_bytes[OFFSET_EXPORT_TABLE_32..OFFSET_EXPORT_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                import_table:                   u64::from_le_bytes(opt_bytes[OFFSET_IMPORT_TABLE_32..OFFSET_IMPORT_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                resource_table:                 u64::from_le_bytes(opt_bytes[OFFSET_RESOURCE_TABLE_32..OFFSET_RESOURCE_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                exception_table:                u64::from_le_bytes(opt_bytes[OFFSET_EXCEPTION_TABLE_32..OFFSET_EXCEPTION_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                certificate_table:              u64::from_le_bytes(opt_bytes[OFFSET_CERTIFICATE_TABLE_32..OFFSET_CERTIFICATE_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                base_relocation_table:          u64::from_le_bytes(opt_bytes[OFFSET_BASE_RELOCATION_TABLE_32..OFFSET_BASE_RELOCATION_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                debug:                          u64::from_le_bytes(opt_bytes[OFFSET_DEBUG_32..OFFSET_DEBUG_32 + 8].try_into().expect("Slice is of incorrect length")),
                architecture:                   u64::from_le_bytes(opt_bytes[OFFSET_ARCHITECTURE_32..OFFSET_ARCHITECTURE_32 + 8].try_into().expect("Slice is of incorrect length")),
                global_ptr:                     u64::from_le_bytes(opt_bytes[OFFSET_GLOBAL_PTR_32..OFFSET_GLOBAL_PTR_32 + 8].try_into().expect("Slice is of incorrect length")),
                tls_table:                      u64::from_le_bytes(opt_bytes[OFFSET_TLS_TABLE_32..OFFSET_TLS_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                load_config_table:              u64::from_le_bytes(opt_bytes[OFFSET_LOAD_CONFIG_TABLE_32..OFFSET_LOAD_CONFIG_TABLE_32 + 8].try_into().expect("Slice is of incorrect length")),
                bound_import:                   u64::from_le_bytes(opt_bytes[OFFSET_BOUND_IMPORT_32..OFFSET_BOUND_IMPORT_32 + 8].try_into().expect("Slice is of incorrect length")),
                iat:                            u64::from_le_bytes(opt_bytes[OFFSET_IAT_32..OFFSET_IAT_32 + 8].try_into().expect("Slice is of incorrect length")),
                delay_import_descriptor:        u64::from_le_bytes(opt_bytes[OFFSET_DELAY_IMPORT_DESCRIPTOR_32..OFFSET_DELAY_IMPORT_DESCRIPTOR_32 + 8].try_into().expect("Slice is of incorrect length")),
                clr_runtime_header:             u64::from_le_bytes(opt_bytes[OFFSET_CLR_RUNTIME_HEADER_32..OFFSET_CLR_RUNTIME_HEADER_32 + 8].try_into().expect("Slice is of incorrect length")),
            }
        }
        else if magic == MAGIC_PE64 {
            OptionalHeader {
                magic:                          u16::from_le_bytes(opt_bytes[OFFSET_MAGIC..OFFSET_MAGIC + 2].try_into().expect("Slice is of incorrect length")),
                major_linker_version:           u8::from_le_bytes(opt_bytes[OFFSET_MAJOR_LINKER_VERSION..OFFSET_MAJOR_LINKER_VERSION + 1].try_into().expect("Slice is of incorrect length")),
                minor_linker_version:           u8::from_le_bytes(opt_bytes[OFFSET_MINOR_LINKER_VERSION..OFFSET_MINOR_LINKER_VERSION + 1].try_into().expect("Slice is of incorrect length")),
                size_of_code:                   u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_CODE..OFFSET_SIZE_OF_CODE + 4].try_into().expect("Slice is of incorrect length")),
                size_of_initialized_data:       u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_INITIALIZED_DATA..OFFSET_SIZE_OF_INITIALIZED_DATA + 4].try_into().expect("Slice is of incorrect length")),
                size_of_uninitialized_data:     u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_UNINITIALIZED_DATA..OFFSET_SIZE_OF_UNINITIALIZED_DATA + 4].try_into().expect("Slice is of incorrect length")),
                address_of_entry_point:         u32::from_le_bytes(opt_bytes[OFFSET_ADDRESS_OF_ENTRY_POINT..OFFSET_ADDRESS_OF_ENTRY_POINT + 4].try_into().expect("Slice is of incorrect length")),
                base_of_code:                   u32::from_le_bytes(opt_bytes[OFFSET_BASE_OF_CODE..OFFSET_BASE_OF_CODE + 4].try_into().expect("Slice is of incorrect length")),
                base_of_data:                   0, // Only used in 32 bit executables.
                image_base:                     u64::from_le_bytes(opt_bytes[OFFSET_IMAGE_BASE_64..OFFSET_IMAGE_BASE_64 + 8].try_into().expect("Slice is of incorrect length")),
                section_alignment:              u32::from_le_bytes(opt_bytes[OFFSET_SECTION_ALIGNMENT..OFFSET_SECTION_ALIGNMENT + 4].try_into().expect("Slice is of incorrect length")),
                file_alignment:                 u32::from_le_bytes(opt_bytes[OFFSET_FILE_ALIGNMENT..OFFSET_FILE_ALIGNMENT + 4].try_into().expect("Slice is of incorrect length")),
                major_operating_system_version: u16::from_le_bytes(opt_bytes[OFFSET_MAJOR_OPERATING_SYSTEM_VERSION..OFFSET_MAJOR_OPERATING_SYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                minor_operating_system_version: u16::from_le_bytes(opt_bytes[OFFSET_MINOR_OPERATING_SYSTEM_VERSION..OFFSET_MINOR_OPERATING_SYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                major_image_version:            u16::from_le_bytes(opt_bytes[OFFSET_MAJOR_IMAGE_VERSION..OFFSET_MAJOR_IMAGE_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                minor_image_version:            u16::from_le_bytes(opt_bytes[OFFSET_MINOR_IMAGE_VERSION..OFFSET_MINOR_IMAGE_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                major_subsystem_version:        u16::from_le_bytes(opt_bytes[OFFSET_MAJOR_SUBSYSTEM_VERSION..OFFSET_MAJOR_SUBSYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                minor_subsystem_version:        u16::from_le_bytes(opt_bytes[OFFSET_MINOR_SUBSYSTEM_VERSION..OFFSET_MINOR_SUBSYSTEM_VERSION + 2].try_into().expect("Slice is of incorrect length")),
                win32_version_value:            u32::from_le_bytes(opt_bytes[OFFSET_WIN32_VERSION_VALUE..OFFSET_WIN32_VERSION_VALUE + 4].try_into().expect("Slice is of incorrect length")),
                size_of_image:                  u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_IMAGE..OFFSET_SIZE_OF_IMAGE + 4].try_into().expect("Slice is of incorrect length")),
                size_of_headers:                u32::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_HEADERS..OFFSET_SIZE_OF_HEADERS + 4].try_into().expect("Slice is of incorrect length")),
                checksum:                       u32::from_le_bytes(opt_bytes[OFFSET_CHECKSUM..OFFSET_CHECKSUM + 4].try_into().expect("Slice is of incorrect length")),
                subsystem:                      u16::from_le_bytes(opt_bytes[OFFSET_SUBSYSTEM..OFFSET_SUBSYSTEM + 2].try_into().expect("Slice is of incorrect length")),
                dll_characteristics:            u16::from_le_bytes(opt_bytes[OFFSET_DLL_CHARACTERISTICS..OFFSET_DLL_CHARACTERISTICS + 2].try_into().expect("Slice is of incorrect length")),
                size_of_stack_reserve:          u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_STACK_RESERVE..OFFSET_SIZE_OF_STACK_RESERVE + 8].try_into().expect("Slice is of incorrect length")),
                size_of_stack_commit:           u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_STACK_COMMIT_64..OFFSET_SIZE_OF_STACK_COMMIT_64 + 8].try_into().expect("Slice is of incorrect length")),
                size_of_heap_reserve:           u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_HEAP_RESERVE_64..OFFSET_SIZE_OF_HEAP_RESERVE_64 + 8].try_into().expect("Slice is of incorrect length")),
                size_of_heap_commit:            u64::from_le_bytes(opt_bytes[OFFSET_SIZE_OF_HEAP_COMMIT_64..OFFSET_SIZE_OF_HEAP_COMMIT_64 + 8].try_into().expect("Slice is of incorrect length")),
                loader_flags:                   u32::from_le_bytes(opt_bytes[OFFSET_LOADER_FLAGS_64..OFFSET_LOADER_FLAGS_64 + 4].try_into().expect("Slice is of incorrect length")),
                number_of_rva_and_sizes:        u32::from_le_bytes(opt_bytes[OFFSET_NUMBER_OF_RVA_AND_SIZES_64..OFFSET_NUMBER_OF_RVA_AND_SIZES_64 + 4].try_into().expect("Slice is of incorrect length")),
                export_table:                   u64::from_le_bytes(opt_bytes[OFFSET_EXPORT_TABLE_64..OFFSET_EXPORT_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                import_table:                   u64::from_le_bytes(opt_bytes[OFFSET_IMPORT_TABLE_64..OFFSET_IMPORT_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                resource_table:                 u64::from_le_bytes(opt_bytes[OFFSET_RESOURCE_TABLE_64..OFFSET_RESOURCE_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                exception_table:                u64::from_le_bytes(opt_bytes[OFFSET_EXCEPTION_TABLE_64..OFFSET_EXCEPTION_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                certificate_table:              u64::from_le_bytes(opt_bytes[OFFSET_CERTIFICATE_TABLE_64..OFFSET_CERTIFICATE_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                base_relocation_table:          u64::from_le_bytes(opt_bytes[OFFSET_BASE_RELOCATION_TABLE_64..OFFSET_BASE_RELOCATION_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                debug:                          u64::from_le_bytes(opt_bytes[OFFSET_DEBUG_64..OFFSET_DEBUG_64 + 8].try_into().expect("Slice is of incorrect length")),
                architecture:                   u64::from_le_bytes(opt_bytes[OFFSET_ARCHITECTURE_64..OFFSET_ARCHITECTURE_64 + 8].try_into().expect("Slice is of incorrect length")),
                global_ptr:                     u64::from_le_bytes(opt_bytes[OFFSET_GLOBAL_PTR_64..OFFSET_GLOBAL_PTR_64 + 8].try_into().expect("Slice is of incorrect length")),
                tls_table:                      u64::from_le_bytes(opt_bytes[OFFSET_TLS_TABLE_64..OFFSET_TLS_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                load_config_table:              u64::from_le_bytes(opt_bytes[OFFSET_LOAD_CONFIG_TABLE_64..OFFSET_LOAD_CONFIG_TABLE_64 + 8].try_into().expect("Slice is of incorrect length")),
                bound_import:                   u64::from_le_bytes(opt_bytes[OFFSET_BOUND_IMPORT_64..OFFSET_BOUND_IMPORT_64 + 8].try_into().expect("Slice is of incorrect length")),
                iat:                            u64::from_le_bytes(opt_bytes[OFFSET_IAT_64..OFFSET_IAT_64 + 8].try_into().expect("Slice is of incorrect length")),
                delay_import_descriptor:        u64::from_le_bytes(opt_bytes[OFFSET_DELAY_IMPORT_DESCRIPTOR_64..OFFSET_DELAY_IMPORT_DESCRIPTOR_64 + 8].try_into().expect("Slice is of incorrect length")),
                clr_runtime_header:             u64::from_le_bytes(opt_bytes[OFFSET_CLR_RUNTIME_HEADER_64..OFFSET_CLR_RUNTIME_HEADER_64 + 8].try_into().expect("Slice is of incorrect length")),
            }
        }
        else {
            panic!("Malformed PE magic!");
        }
    }
}
