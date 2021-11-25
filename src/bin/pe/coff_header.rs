use std::convert::TryInto;

const OFFSET_MACHINE:                 usize = 0x00;
const OFFSET_NUMBER_OF_SECTIONS:      usize = 0x02;
const OFFSET_TIMEDATE_STAMP:          usize = 0x04;
const OFFSET_POINTER_TO_SYMBOL_TABLE: usize = 0x08;
const OFFSET_NUMBER_OF_SYMBOLS:       usize = 0x0C;
const OFFSET_SIZE_OF_OPTIONAL_HEADER: usize = 0x10;
const OFFSET_CHARACTERISTICS:         usize = 0x12;

#[derive(Debug)]
pub struct CoffHeader {
    // The number that identifies the type of target machine. For more
    // information, see Machine Types.
    pub machine: u16,

    // The number of sections. This indicates the size of the section table,
    // which immediately follows the headers.
    pub number_of_sections: u16,

    // The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a
    // C run-time time_t value), which indicates when the file was created.
    pub timedate_stamp: u32,

    // The file offset of the COFF symbol table, or zero if no COFF symbol table
    // is present. This value should be zero for an image because COFF debugging
    // information is deprecated.
    pub pointer_to_symbol_table: u32,

    // The number of entries in the symbol table. This data can be used to
    // locate the string table, which immediately follows the symbol table. This
    // value should be zero for an image because COFF debugging information is
    // deprecated.
    pub number_of_symbols: u32,

    // The size of the optional header, which is required for executable files
    // but not for object files. This value should be zero for an object file.
    // For a description of the header format, see Optional Header (Image Only).
    pub size_of_optional_header: u16,

    // The flags that indicate the attributes of the file. For specific flag
    // values.
    pub characteristics: u16,
}

impl CoffHeader {
    pub fn new(hdr_bytes: &[u8]) -> CoffHeader {
        CoffHeader {
            machine:                 u16::from_le_bytes(hdr_bytes[OFFSET_MACHINE..OFFSET_MACHINE + 2].try_into().expect("Slice is of incorrect length")),
            number_of_sections:      u16::from_le_bytes(hdr_bytes[OFFSET_NUMBER_OF_SECTIONS..OFFSET_NUMBER_OF_SECTIONS + 2].try_into().expect("Slice is of incorrect length")),
            timedate_stamp:          u32::from_le_bytes(hdr_bytes[OFFSET_TIMEDATE_STAMP..OFFSET_TIMEDATE_STAMP + 4].try_into().expect("Slice is of incorrect length")),
            pointer_to_symbol_table: u32::from_le_bytes(hdr_bytes[OFFSET_POINTER_TO_SYMBOL_TABLE..OFFSET_POINTER_TO_SYMBOL_TABLE + 4].try_into().expect("Slice is of incorrect length")),
            number_of_symbols:       u32::from_le_bytes(hdr_bytes[OFFSET_NUMBER_OF_SYMBOLS..OFFSET_NUMBER_OF_SYMBOLS + 4].try_into().expect("Slice is of incorrect length")),
            size_of_optional_header: u16::from_le_bytes(hdr_bytes[OFFSET_SIZE_OF_OPTIONAL_HEADER..OFFSET_SIZE_OF_OPTIONAL_HEADER + 2].try_into().expect("Slice is of incorrect length")),
            characteristics:         u16::from_le_bytes(hdr_bytes[OFFSET_CHARACTERISTICS..OFFSET_CHARACTERISTICS + 2].try_into().expect("Slice is of incorrect length")),
        }
    }
}
