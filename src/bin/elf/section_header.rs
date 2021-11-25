use std::convert::TryInto;

const OFFSET_SH_NAME:         usize = 0x00;
const OFFSET_SH_TYPE:         usize = 0x04;
const OFFSET_SH_FLAGS:        usize = 0x08;
const OFFSET_SH_ADDR_32:      usize = 0x0C;
const OFFSET_SH_OFFSET_32:    usize = 0x10;
const OFFSET_SH_SIZE_32:      usize = 0x14;
const OFFSET_SH_LINK_32:      usize = 0x18;
const OFFSET_SH_INFO_32:      usize = 0x1C;
const OFFSET_SH_ADDRALIGN_32: usize = 0x20;
const OFFSET_SH_ENTSIZE_32:   usize = 0x24;
const OFFSET_SH_ADDR_64:      usize = 0x10;
const OFFSET_SH_OFFSET_64:    usize = 0x18;
const OFFSET_SH_SIZE_64:      usize = 0x20;
const OFFSET_SH_LINK_64:      usize = 0x28;
const OFFSET_SH_INFO_64:      usize = 0x2C;
const OFFSET_SH_ADDRALIGN_64: usize = 0x30;
const OFFSET_SH_ENTSIZE_64:   usize = 0x38;

const LSB:   u8 = 1;
const MSB:   u8 = 2;
const BIT32: u8 = 1;
const BIT64: u8 = 2;

#[derive(Debug)]
pub struct SectionHeader {
    // An offset to a string in the .shstrtab section that represents the
    // name of this section.
    pub sh_name: u32,

    // Identifies the type of this header.
    pub sh_type: u32,

    // Identifies the attributes of the section.
    pub sh_flags: u64,

    // Virtual address of the section in memory, for sections that are
    // loaded.
    pub sh_addr: u64,

    // Offset of the section in the file image.
    pub sh_offset: u64,

    // Size in bytes of the section in the file image. May be 0.
    pub sh_size: u64,

    // Contains the section index of an associated section. This field is
    // used for several purposes, depending on the type of section.
    pub sh_link: u32,

    // Contains extra information about the section. This field is used for
    // several purposes, depending on the type of section.
    pub sh_info: u32,

    // Contains the required alignment of the section. This field must be a
    // power of two.
    pub sh_addralign: u64,

    // Contains the size, in bytes, of each entry, for sections that contain
    // fixed-size entries. Otherwise, this field contains zero.
    pub sh_entsize: u64,
}

impl SectionHeader {
    pub fn new(sh_bytes: &[u8], endianess: u8, bitsize: u8) -> SectionHeader {
        if bitsize == BIT64 {
            if endianess == LSB {
                SectionHeader {
                    sh_name:      u32::from_le_bytes(sh_bytes[OFFSET_SH_NAME..OFFSET_SH_NAME + 4].try_into().expect("Slice has incorrect length")),
                    sh_type:      u32::from_le_bytes(sh_bytes[OFFSET_SH_TYPE..OFFSET_SH_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    sh_flags:     u64::from_le_bytes(sh_bytes[OFFSET_SH_FLAGS..OFFSET_SH_FLAGS + 8].try_into().expect("Slice has incorrect length")),
                    sh_addr:      u64::from_le_bytes(sh_bytes[OFFSET_SH_ADDR_64..OFFSET_SH_ADDR_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_offset:    u64::from_le_bytes(sh_bytes[OFFSET_SH_OFFSET_64..OFFSET_SH_OFFSET_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_size:      u64::from_le_bytes(sh_bytes[OFFSET_SH_SIZE_64..OFFSET_SH_SIZE_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_link:      u32::from_le_bytes(sh_bytes[OFFSET_SH_LINK_64..OFFSET_SH_LINK_64 + 4].try_into().expect("Slice has incorrect length")),
                    sh_info:      u32::from_le_bytes(sh_bytes[OFFSET_SH_INFO_64..OFFSET_SH_INFO_64 + 4].try_into().expect("Slice has incorrect length")),
                    sh_addralign: u64::from_le_bytes(sh_bytes[OFFSET_SH_ADDRALIGN_64..OFFSET_SH_ADDRALIGN_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_entsize:   u64::from_le_bytes(sh_bytes[OFFSET_SH_ENTSIZE_64..OFFSET_SH_ENTSIZE_64 + 8].try_into().expect("Slice has incorrect length")),
                }
            }
            else if endianess == MSB {
                SectionHeader {
                    sh_name:      u32::from_be_bytes(sh_bytes[OFFSET_SH_NAME..OFFSET_SH_NAME + 4].try_into().expect("Slice has incorrect length")),
                    sh_type:      u32::from_be_bytes(sh_bytes[OFFSET_SH_TYPE..OFFSET_SH_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    sh_flags:     u64::from_be_bytes(sh_bytes[OFFSET_SH_FLAGS..OFFSET_SH_FLAGS + 8].try_into().expect("Slice has incorrect length")),
                    sh_addr:      u64::from_be_bytes(sh_bytes[OFFSET_SH_ADDR_64..OFFSET_SH_ADDR_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_offset:    u64::from_be_bytes(sh_bytes[OFFSET_SH_OFFSET_64..OFFSET_SH_OFFSET_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_size:      u64::from_be_bytes(sh_bytes[OFFSET_SH_SIZE_64..OFFSET_SH_SIZE_64].try_into().expect("Slice has incorrect length")),
                    sh_link:      u32::from_be_bytes(sh_bytes[OFFSET_SH_LINK_64..OFFSET_SH_LINK_64 + 4].try_into().expect("Slice has incorrect length")),
                    sh_info:      u32::from_be_bytes(sh_bytes[OFFSET_SH_INFO_64..OFFSET_SH_INFO_64 + 4].try_into().expect("Slice has incorrect length")),
                    sh_addralign: u64::from_be_bytes(sh_bytes[OFFSET_SH_ADDRALIGN_64..OFFSET_SH_ADDRALIGN_64 + 8].try_into().expect("Slice has incorrect length")),
                    sh_entsize:   u64::from_be_bytes(sh_bytes[OFFSET_SH_ENTSIZE_64..OFFSET_SH_ENTSIZE_64 + 8].try_into().expect("Slice has incorrect length")),
                }
            }
            else {
                panic!("Malformed section header!");
            }
        }
        else if bitsize == BIT32 {
            if endianess == LSB {
                SectionHeader {
                    sh_name:      u32::from_le_bytes(sh_bytes[OFFSET_SH_NAME..OFFSET_SH_NAME + 4].try_into().expect("Slice has incorrect length")),
                    sh_type:      u32::from_le_bytes(sh_bytes[OFFSET_SH_TYPE..OFFSET_SH_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    sh_flags:     u32::from_le_bytes(sh_bytes[OFFSET_SH_FLAGS..OFFSET_SH_FLAGS + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_addr:      u32::from_le_bytes(sh_bytes[OFFSET_SH_ADDR_32..OFFSET_SH_ADDR_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_offset:    u32::from_le_bytes(sh_bytes[OFFSET_SH_OFFSET_32..OFFSET_SH_OFFSET_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_size:      u32::from_le_bytes(sh_bytes[OFFSET_SH_SIZE_32..OFFSET_SH_SIZE_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_link:      u32::from_le_bytes(sh_bytes[OFFSET_SH_LINK_32..OFFSET_SH_LINK_32 + 4].try_into().expect("Slice has incorrect length")),
                    sh_info:      u32::from_le_bytes(sh_bytes[OFFSET_SH_INFO_32..OFFSET_SH_INFO_32 + 4].try_into().expect("Slice has incorrect length")),
                    sh_addralign: u32::from_le_bytes(sh_bytes[OFFSET_SH_ADDRALIGN_32..OFFSET_SH_ADDRALIGN_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_entsize:   u32::from_le_bytes(sh_bytes[OFFSET_SH_ENTSIZE_32..OFFSET_SH_ENTSIZE_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                }
            }
            else if endianess == MSB {
                SectionHeader {
                    sh_name:      u32::from_be_bytes(sh_bytes[OFFSET_SH_NAME..OFFSET_SH_NAME + 4].try_into().expect("Slice has incorrect length")),
                    sh_type:      u32::from_be_bytes(sh_bytes[OFFSET_SH_TYPE..OFFSET_SH_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    sh_flags:     u32::from_be_bytes(sh_bytes[OFFSET_SH_FLAGS..OFFSET_SH_FLAGS + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_addr:      u32::from_be_bytes(sh_bytes[OFFSET_SH_ADDR_32..OFFSET_SH_ADDR_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_offset:    u32::from_be_bytes(sh_bytes[OFFSET_SH_OFFSET_32..OFFSET_SH_OFFSET_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_size:      u32::from_be_bytes(sh_bytes[OFFSET_SH_SIZE_32..OFFSET_SH_SIZE_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_link:      u32::from_be_bytes(sh_bytes[OFFSET_SH_LINK_32..OFFSET_SH_LINK_32 + 4].try_into().expect("Slice has incorrect length")),
                    sh_info:      u32::from_be_bytes(sh_bytes[OFFSET_SH_INFO_32..OFFSET_SH_INFO_32 + 4].try_into().expect("Slice has incorrect length")),
                    sh_addralign: u32::from_be_bytes(sh_bytes[OFFSET_SH_ADDRALIGN_32..OFFSET_SH_ADDRALIGN_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    sh_entsize:   u32::from_be_bytes(sh_bytes[OFFSET_SH_ENTSIZE_32..OFFSET_SH_ENTSIZE_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                }
            }
            else {
                panic!("Malformed section header!");
            }
        }
        else {
            panic!("Malformed section header!");
        }
    }
}
