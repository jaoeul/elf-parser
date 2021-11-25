use crate::program_header::ProgramHeader;
use crate::section_header::SectionHeader;
use std::convert::TryInto;

// Offsets of fields in a elf header.
const OFFSET_E_IDENT:        usize = 0x00;
const OFFSET_E_TYPE:         usize = 0x10;
const OFFSET_E_MACHINE:      usize = 0x12;
const OFFSET_E_VERSION:      usize = 0x14;
const OFFSET_E_ENTRY:        usize = 0x18;
const OFFSET_E_PHOFF_32:     usize = 0x1C;
const OFFSET_E_PHOFF_64:     usize = 0x20;
const OFFSET_E_SHOFF_32:     usize = 0x20;
const OFFSET_E_SHOFF_64:     usize = 0x28;
const OFFSET_E_FLAGS_32:     usize = 0x24;
const OFFSET_E_FLAGS_64:     usize = 0x30;
const OFFSET_E_EHSIZE_32:    usize = 0x28;
const OFFSET_E_EHSIZE_64:    usize = 0x34;
const OFFSET_E_PHENTSIZE_32: usize = 0x2A;
const OFFSET_E_PHENTSIZE_64: usize = 0x36;
const OFFSET_E_PHNUM_32:     usize = 0x2C;
const OFFSET_E_PHNUM_64:     usize = 0x38;
const OFFSET_E_SHENTSIZE_32: usize = 0x2E;
const OFFSET_E_SHENTSIZE_64: usize = 0x3A;
const OFFSET_E_SHNUM_32:     usize = 0x30;
const OFFSET_E_SHNUM_64:     usize = 0x3C;
const OFFSET_E_SHSTRNDX_32:  usize = 0x32;
const OFFSET_E_SHSTRNDX_64:  usize = 0x3E;

const ELF_VERSION_ORIGINAL: u8 = 1;

const EI_MAG0:       usize = 0x00;
const EI_MAG1:       usize = 0x01;
const EI_MAG2:       usize = 0x02;
const EI_MAG3:       usize = 0x03;
const EI_CLASS:      usize = 0x04;
const EI_DATA:       usize = 0x05;
const EI_VERSION:    usize = 0x06;
const EI_OSABI:      usize = 0x07;
const EI_ABIVERSION: usize = 0x08;
const EI_PAD:        usize = 0x09;

const LSB:   u8 = 1;
const MSB:   u8 = 2;
const BIT32: u8 = 1;
const BIT64: u8 = 2;

#[derive(Debug)]
pub struct ElfHeader {
    // e_ident[EI_MAG0] through e_ident[EI_MAG3] - 0x7F followed by ELF(45 4c 46) in ASCII; these four bytes constitute the magic number.
    // e_ident[EI_CLASS] - This byte is set to either 1 or 2 to signify 32- or 64-bit format, respectively.
    // e_ident[EI_DATA] - This byte is set to either 1 or 2 to signify little or big endianness, respectively. This affects interpretation of multi-byte fields starting with offset 0x10.
    // e_ident[EI_VERSION] - Set to 1 for the original and current version of ELF.
    // e_ident[EI_OSABI] - Identifies the target operating system ABI.
    // e_ident[EI_ABIVERSION] - Further specifies the ABI version. Its interpretation depends on the target ABI. Linux kernel (after at least 2.6) has no definition of it,[6] so it is ignored for statically-linked executables. In that case, offset and size of EI_PAD are 8.
    // e_ident[EI_PAD] - Currently unused, should be filled with zeros.
    pub e_ident: [u8; 0x10],

    // Identifies object file type.
    pub e_type: u16,

    // Specifies target instruction set architecture.
    pub e_machine: u16,

    // Set to 1 for the original version of ELF.
    pub e_version: u32,

    // This is the memory address of the entry point from where the process
    // starts executing. This field is either 32 or 64 bits long depending on
    // the format defined earlier.
    pub e_entry: u64,

    // Points to the start of the program header table. It usually follows the
    // file header immediately, making the offset 0x34 or 0x40 for 32- and
    // 64-bit ELF executables, respectively.
    pub e_phoff: u64,

    // Points to the start of the section header table.
    pub e_shoff: u64,

    // Interpretation of this field depends on the target architecture.
    pub e_flags: u32,

    // Contains the size of this header, normally 64 Bytes for 64-bit and 52
    // Bytes for 32-bit format.
    pub e_ehsize: u16,

    // Contains the size of a program header table entry.
    pub e_phentsize: u16,

    // Contains the number of entries in the program header table.
    pub e_phnum: u16,

    // Contains the size of a section header table entry.
    pub e_shentsize: u16,

    // Contains the number of entries in the section header table.
    pub e_shnum: u16,

    // Contains index of the section header table entry that contains the
    // section names.
    pub e_shstrndx: u16,
}

impl ElfHeader {
    pub fn new(raw_bytes: &Vec<u8>, endianess: u8, bitsize: u8) -> ElfHeader {
        if bitsize == BIT64 {
            if endianess == LSB {
                ElfHeader {
                    e_ident:     raw_bytes[OFFSET_E_IDENT..OFFSET_E_IDENT + 0x10].try_into().expect("Slice has incorrect length"),
                    e_type:      u16::from_le_bytes(raw_bytes[OFFSET_E_TYPE..OFFSET_E_TYPE + 2].try_into().expect("Slice has incorrect length")),
                    e_machine:   u16::from_le_bytes(raw_bytes[OFFSET_E_MACHINE..OFFSET_E_MACHINE + 2].try_into().expect("Slice has incorrect length")),
                    e_version:   u32::from_le_bytes(raw_bytes[OFFSET_E_VERSION..OFFSET_E_VERSION + 4].try_into().expect("Slice has incorrect length")),
                    e_entry:     u64::from_le_bytes(raw_bytes[OFFSET_E_ENTRY..OFFSET_E_ENTRY + 8].try_into().expect("Slice has incorrect length")),
                    e_phoff:     u64::from_le_bytes(raw_bytes[OFFSET_E_PHOFF_64..OFFSET_E_PHOFF_64 + 8].try_into().expect("Slice has incorrect length")),
                    e_shoff:     u64::from_le_bytes(raw_bytes[OFFSET_E_SHOFF_64..OFFSET_E_SHOFF_64 + 8].try_into().expect("Slice has incorrect length")),
                    e_flags:     u32::from_le_bytes(raw_bytes[OFFSET_E_FLAGS_64..OFFSET_E_FLAGS_64 + 4].try_into().expect("Slice has incorrect length")),
                    e_ehsize:    u16::from_le_bytes(raw_bytes[OFFSET_E_EHSIZE_64..OFFSET_E_EHSIZE_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_phentsize: u16::from_le_bytes(raw_bytes[OFFSET_E_PHENTSIZE_64..OFFSET_E_PHENTSIZE_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_phnum:     u16::from_le_bytes(raw_bytes[OFFSET_E_PHNUM_64..OFFSET_E_PHNUM_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_shentsize: u16::from_le_bytes(raw_bytes[OFFSET_E_SHENTSIZE_64..OFFSET_E_SHENTSIZE_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_shnum:     u16::from_le_bytes(raw_bytes[OFFSET_E_SHNUM_64..OFFSET_E_SHNUM_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_shstrndx:  u16::from_le_bytes(raw_bytes[OFFSET_E_SHSTRNDX_64..OFFSET_E_SHSTRNDX_64 + 2].try_into().expect("Slice has incorrect length")),
                }
            }
            else if endianess == MSB {
                ElfHeader {
                    e_ident:     [0u8; 0x10],
                    e_type:      u16::from_be_bytes(raw_bytes[OFFSET_E_TYPE..OFFSET_E_TYPE + 2].try_into().expect("Slice has incorrect length")),
                    e_machine:   u16::from_be_bytes(raw_bytes[OFFSET_E_MACHINE..OFFSET_E_MACHINE + 2].try_into().expect("Slice has incorrect length")),
                    e_version:   u32::from_be_bytes(raw_bytes[OFFSET_E_VERSION..OFFSET_E_VERSION + 4].try_into().expect("Slice has incorrect length")),
                    e_entry:     u64::from_be_bytes(raw_bytes[OFFSET_E_ENTRY..OFFSET_E_ENTRY + 8].try_into().expect("Slice has incorrect length")),
                    e_phoff:     u64::from_be_bytes(raw_bytes[OFFSET_E_PHOFF_64..OFFSET_E_PHOFF_64 + 8].try_into().expect("Slice has incorrect length")),
                    e_shoff:     u64::from_be_bytes(raw_bytes[OFFSET_E_SHOFF_64..OFFSET_E_SHOFF_64 + 8].try_into().expect("Slice has incorrect length")),
                    e_flags:     u32::from_be_bytes(raw_bytes[OFFSET_E_FLAGS_64..OFFSET_E_FLAGS_64 + 4].try_into().expect("Slice has incorrect length")),
                    e_ehsize:    u16::from_be_bytes(raw_bytes[OFFSET_E_EHSIZE_64..OFFSET_E_EHSIZE_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_phentsize: u16::from_be_bytes(raw_bytes[OFFSET_E_PHENTSIZE_64..OFFSET_E_PHENTSIZE_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_phnum:     u16::from_be_bytes(raw_bytes[OFFSET_E_PHNUM_64..OFFSET_E_PHNUM_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_shentsize: u16::from_be_bytes(raw_bytes[OFFSET_E_SHENTSIZE_64..OFFSET_E_SHENTSIZE_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_shnum:     u16::from_be_bytes(raw_bytes[OFFSET_E_SHNUM_64..OFFSET_E_SHNUM_64 + 2].try_into().expect("Slice has incorrect length")),
                    e_shstrndx:  u16::from_be_bytes(raw_bytes[OFFSET_E_SHSTRNDX_64..OFFSET_E_SHSTRNDX_64 + 2].try_into().expect("Slice has incorrect length")),
                }
            }
            else {
                panic!("Malformed header!");
            }
        }
        else if bitsize == BIT32 {
            if endianess == LSB {
                ElfHeader {
                    e_ident:     [0u8; 0x10],
                    e_type:      u16::from_le_bytes(raw_bytes[OFFSET_E_TYPE..OFFSET_E_TYPE + 2].try_into().expect("Slice has incorrect length")),
                    e_machine:   u16::from_le_bytes(raw_bytes[OFFSET_E_MACHINE..OFFSET_E_MACHINE + 2].try_into().expect("Slice has incorrect length")),
                    e_version:   u32::from_le_bytes(raw_bytes[OFFSET_E_VERSION..OFFSET_E_VERSION + 4].try_into().expect("Slice has incorrect length")),
                    e_entry:     u32::from_le_bytes(raw_bytes[OFFSET_E_ENTRY..OFFSET_E_ENTRY + 4].try_into().expect("Slice has incorrect length")) as u64,
                    e_phoff:     u32::from_le_bytes(raw_bytes[OFFSET_E_PHOFF_32..OFFSET_E_PHOFF_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    e_shoff:     u32::from_le_bytes(raw_bytes[OFFSET_E_SHOFF_32..OFFSET_E_SHOFF_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    e_flags:     u32::from_le_bytes(raw_bytes[OFFSET_E_FLAGS_32..OFFSET_E_FLAGS_32 + 4].try_into().expect("Slice has incorrect length")),
                    e_ehsize:    u16::from_le_bytes(raw_bytes[OFFSET_E_EHSIZE_32..OFFSET_E_EHSIZE_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_phentsize: u16::from_le_bytes(raw_bytes[OFFSET_E_PHENTSIZE_32..OFFSET_E_PHENTSIZE_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_phnum:     u16::from_le_bytes(raw_bytes[OFFSET_E_PHNUM_32..OFFSET_E_PHNUM_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_shentsize: u16::from_le_bytes(raw_bytes[OFFSET_E_SHENTSIZE_32..OFFSET_E_SHENTSIZE_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_shnum:     u16::from_le_bytes(raw_bytes[OFFSET_E_SHNUM_32..OFFSET_E_SHNUM_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_shstrndx:  u16::from_le_bytes(raw_bytes[OFFSET_E_SHSTRNDX_32..OFFSET_E_SHSTRNDX_32 + 2].try_into().expect("Slice has incorrect length")),
                }
            }
            else if endianess == MSB {
                ElfHeader {
                    e_ident: [0u8; 0x10],
                    e_type:      u16::from_be_bytes(raw_bytes[OFFSET_E_TYPE..OFFSET_E_TYPE + 2].try_into().expect("Slice has incorrect length")),
                    e_machine:   u16::from_be_bytes(raw_bytes[OFFSET_E_MACHINE..OFFSET_E_MACHINE + 2].try_into().expect("Slice has incorrect length")),
                    e_version:   u32::from_be_bytes(raw_bytes[OFFSET_E_VERSION..OFFSET_E_VERSION + 4].try_into().expect("Slice has incorrect length")),
                    e_entry:     u32::from_be_bytes(raw_bytes[OFFSET_E_ENTRY..OFFSET_E_ENTRY + 4].try_into().expect("Slice has incorrect length")) as u64,
                    e_phoff:     u32::from_be_bytes(raw_bytes[OFFSET_E_PHOFF_32..OFFSET_E_PHOFF_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    e_shoff:     u32::from_be_bytes(raw_bytes[OFFSET_E_SHOFF_32..OFFSET_E_SHOFF_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    e_flags:     u32::from_be_bytes(raw_bytes[OFFSET_E_FLAGS_32..OFFSET_E_FLAGS_32 + 4].try_into().expect("Slice has incorrect length")),
                    e_ehsize:    u16::from_be_bytes(raw_bytes[OFFSET_E_EHSIZE_32..OFFSET_E_EHSIZE_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_phentsize: u16::from_be_bytes(raw_bytes[OFFSET_E_PHENTSIZE_32..OFFSET_E_PHENTSIZE_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_phnum:     u16::from_be_bytes(raw_bytes[OFFSET_E_PHNUM_32..OFFSET_E_PHNUM_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_shentsize: u16::from_be_bytes(raw_bytes[OFFSET_E_SHENTSIZE_32..OFFSET_E_SHENTSIZE_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_shnum:     u16::from_be_bytes(raw_bytes[OFFSET_E_SHNUM_32..OFFSET_E_SHNUM_32 + 2].try_into().expect("Slice has incorrect length")),
                    e_shstrndx:  u16::from_be_bytes(raw_bytes[OFFSET_E_SHSTRNDX_32..OFFSET_E_SHSTRNDX_32 + 2].try_into().expect("Slice has incorrect length")),
                }
            }
            else {
                panic!("Malformed header!");
            }
        }
        else {
            panic!("Malformed header!");
        }
    }
}

pub struct ElfFile {
    pub path:            String,
    pub raw_bytes:       Vec<u8>,
    pub header:          ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
}

impl std::fmt::Display for ElfFile {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let out_str = format!("
Path: {}
Header: {:#?}
Program headers: {:#?}
Section headers: {:#?}
",                             self.path, self.header,
                               self.program_headers,
                               self.section_headers);
        write!(f, "{}", out_str)
    }
}

impl ElfFile {
    fn probe_valid(raw_bytes: &Vec<u8>) {
        let magic_bytes = [0x7f, 0x45, 0x4c, 0x46];
        assert_eq!(&raw_bytes[0x00..0x04], magic_bytes);
    }

    pub fn new(path: &str) -> ElfFile {
        let raw_bytes = std::fs::read(path).unwrap();
        ElfFile::probe_valid(&raw_bytes);
        let bitsize:   u8 = raw_bytes[OFFSET_E_IDENT + EI_CLASS];
        let endianess: u8 = raw_bytes[OFFSET_E_IDENT + EI_DATA];

        // Parse the elf header.
        let header = ElfHeader::new(&raw_bytes, endianess, bitsize);

        // Parse the program headers.
        let mut program_headers: Vec<ProgramHeader> = Vec::new();
        let mut i: usize = header.e_phoff as usize;
        while i < (header.e_phoff + (header.e_phentsize * header.e_phnum) as u64) as usize {
            program_headers.push(ProgramHeader::new(&raw_bytes[i..i + header.e_phentsize as usize], endianess, bitsize));
            i += header.e_phentsize as usize;
        }

        // Parse the section headers.
        let mut section_headers: Vec<SectionHeader> = Vec::new();
        let mut i: usize  = header.e_shoff as usize;
        while i < (header.e_shoff + (header.e_shentsize * header.e_shnum) as u64) as usize {
            section_headers.push(SectionHeader::new(&raw_bytes[i..i + header.e_shentsize as usize], endianess, bitsize));
            i += header.e_shentsize as usize;
        }

        ElfFile {
            path:            path.to_string(),
            header:          header,
            program_headers: program_headers,
            section_headers: section_headers,
            raw_bytes:       raw_bytes,
        }
    }
}
