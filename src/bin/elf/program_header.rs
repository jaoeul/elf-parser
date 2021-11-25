use std::convert::TryInto;

const OFFSET_P_TYPE:      usize = 0x00;
const OFFSET_P_FLAGS_32:  usize = 0x18;
const OFFSET_P_FLAGS_64:  usize = 0x04;
const OFFSET_P_OFFSET_32: usize = 0x04;
const OFFSET_P_OFFSET_64: usize = 0x08;
const OFFSET_P_VADDR_32:  usize = 0x08;
const OFFSET_P_VADDR_64:  usize = 0x10;
const OFFSET_P_PADDR_32:  usize = 0x0C;
const OFFSET_P_PADDR_64:  usize = 0x18;
const OFFSET_P_FILESZ_32: usize = 0x10;
const OFFSET_P_FILESZ_64: usize = 0x20;
const OFFSET_P_MEMSZ_32:  usize = 0x14;
const OFFSET_P_MEMSZ_64:  usize = 0x28;
const OFFSET_P_ALIGN_32:  usize = 0x1C;
const OFFSET_P_ALIGN_64:  usize = 0x30;

const LSB:   u8 = 1;
const MSB:   u8 = 2;
const BIT32: u8 = 1;
const BIT64: u8 = 2;

#[derive(Debug)]
pub struct ProgramHeader {
    // Identifies the type of the segment.
    pub p_type: u32,

    // Segment-dependent flags (position for 64-bit structure).
    pub p_flags: u32,

    // Offset of the segment in the file image.
    pub p_offset: u64,

    // Virtual address of the segment in memory.
    pub p_vaddr: u64,

    // On systems where physical address is relevant, reserved for segment's
    // physical address.
    pub p_paddr: u64,

    // Size in bytes of the segment in the file image. May be 0.
    pub p_filesz: u64,

    // Size in bytes of the segment in memory. May be 0.
    pub p_memsz: u64,

    // 0 and 1 specify no alignment. Otherwise should be a positive, integral
    // power of 2, with p_vaddr equating p_offset modulus p_align.
    pub p_align: u64,
}

impl ProgramHeader {
    pub fn new(ph_bytes: &[u8], endianess: u8, bitsize: u8) -> ProgramHeader {
        if bitsize == BIT64 {
            if endianess == LSB {
                ProgramHeader {
                    p_type:   u32::from_le_bytes(ph_bytes[OFFSET_P_TYPE..OFFSET_P_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    p_flags:  u32::from_le_bytes(ph_bytes[OFFSET_P_FLAGS_64..OFFSET_P_FLAGS_64 + 4].try_into().expect("Slice has incorrect length")),
                    p_offset: u64::from_le_bytes(ph_bytes[OFFSET_P_OFFSET_64..OFFSET_P_OFFSET_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_vaddr:  u64::from_le_bytes(ph_bytes[OFFSET_P_VADDR_64..OFFSET_P_VADDR_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_paddr:  u64::from_le_bytes(ph_bytes[OFFSET_P_PADDR_64..OFFSET_P_PADDR_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_filesz: u64::from_le_bytes(ph_bytes[OFFSET_P_FILESZ_64..OFFSET_P_FILESZ_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_memsz:  u64::from_le_bytes(ph_bytes[OFFSET_P_MEMSZ_64..OFFSET_P_MEMSZ_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_align:  u64::from_le_bytes(ph_bytes[OFFSET_P_ALIGN_64..OFFSET_P_ALIGN_64 + 8].try_into().expect("Slice has incorrect length")),
                }
            }
            else if endianess == MSB {
                ProgramHeader {
                    p_type:   u32::from_be_bytes(ph_bytes[OFFSET_P_TYPE..OFFSET_P_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    p_flags:  u32::from_be_bytes(ph_bytes[OFFSET_P_FLAGS_64..OFFSET_P_FLAGS_64 + 4].try_into().expect("Slice has incorrect length")),
                    p_offset: u64::from_be_bytes(ph_bytes[OFFSET_P_OFFSET_64..OFFSET_P_OFFSET_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_vaddr:  u64::from_be_bytes(ph_bytes[OFFSET_P_VADDR_64..OFFSET_P_VADDR_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_paddr:  u64::from_be_bytes(ph_bytes[OFFSET_P_PADDR_64..OFFSET_P_PADDR_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_filesz: u64::from_be_bytes(ph_bytes[OFFSET_P_FILESZ_64..OFFSET_P_FILESZ_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_memsz:  u64::from_be_bytes(ph_bytes[OFFSET_P_MEMSZ_64..OFFSET_P_MEMSZ_64 + 8].try_into().expect("Slice has incorrect length")),
                    p_align:  u64::from_be_bytes(ph_bytes[OFFSET_P_ALIGN_64..OFFSET_P_ALIGN_64 + 8].try_into().expect("Slice has incorrect length")),
                }
            }
            else {
                panic!("Malformed program header!");
            }
        }
        else if bitsize == BIT32 {
            if endianess == LSB {
                ProgramHeader {
                    p_type:   u32::from_le_bytes(ph_bytes[OFFSET_P_TYPE..OFFSET_P_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    p_flags:  u32::from_le_bytes(ph_bytes[OFFSET_P_FLAGS_32..OFFSET_P_FLAGS_32 + 4].try_into().expect("Slice has incorrect length")),
                    p_offset: u32::from_le_bytes(ph_bytes[OFFSET_P_OFFSET_32..OFFSET_P_OFFSET_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_vaddr:  u32::from_le_bytes(ph_bytes[OFFSET_P_VADDR_32..OFFSET_P_VADDR_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_paddr:  u32::from_le_bytes(ph_bytes[OFFSET_P_PADDR_32..OFFSET_P_PADDR_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_filesz: u32::from_le_bytes(ph_bytes[OFFSET_P_FILESZ_32..OFFSET_P_FILESZ_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_memsz:  u32::from_le_bytes(ph_bytes[OFFSET_P_MEMSZ_32..OFFSET_P_MEMSZ_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_align:  u32::from_le_bytes(ph_bytes[OFFSET_P_ALIGN_32..OFFSET_P_ALIGN_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                }
            }
            else if endianess == MSB {
                ProgramHeader {
                    p_type:   u32::from_be_bytes(ph_bytes[OFFSET_P_TYPE..OFFSET_P_TYPE + 4].try_into().expect("Slice has incorrect length")),
                    p_flags:  u32::from_be_bytes(ph_bytes[OFFSET_P_FLAGS_32..OFFSET_P_FLAGS_32 + 4].try_into().expect("Slice has incorrect length")),
                    p_offset: u32::from_be_bytes(ph_bytes[OFFSET_P_OFFSET_32..OFFSET_P_OFFSET_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_vaddr:  u32::from_be_bytes(ph_bytes[OFFSET_P_VADDR_32..OFFSET_P_VADDR_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_paddr:  u32::from_be_bytes(ph_bytes[OFFSET_P_PADDR_32..OFFSET_P_PADDR_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_filesz: u32::from_be_bytes(ph_bytes[OFFSET_P_FILESZ_32..OFFSET_P_FILESZ_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_memsz:  u32::from_be_bytes(ph_bytes[OFFSET_P_MEMSZ_32..OFFSET_P_MEMSZ_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                    p_align:  u32::from_be_bytes(ph_bytes[OFFSET_P_ALIGN_32..OFFSET_P_ALIGN_32 + 4].try_into().expect("Slice has incorrect length")) as u64,
                }
            }
            else {
                panic!("Malformed program header!");
            }
        }
        else {
            panic!("Malformed program header!");
        }
    }
}
