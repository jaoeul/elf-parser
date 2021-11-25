use crate::coff_header::CoffHeader;
use crate::optional_header::OptionalHeader;
use std::convert::TryInto;

const MS_DOS_HEADER_SIZE:          usize = 0x40;
const PE_SIGNATURE_POINTER_OFFSET: usize = 0x3C;
const PE_SIGNATURE_SIZE:           usize = 0x04;
const COFF_HEADER_SIZE:            usize = 0x14;

#[derive(Debug)]
pub struct PEFile {
    pub path:            String,
    pub signature:       [u8; 4],
    pub ms_dos_stub_hdr: [u8; 64],
    pub coff_header:     CoffHeader,
    pub optional_header: OptionalHeader,
}

impl PEFile {
    fn validate_pe_signature(sig: [u8; 4]) {
        let pe_signature = [0x50, 0x45, 0x00, 0x00]; // PE\x00\x00
        assert_eq!(sig, pe_signature);
    }

    pub fn new(path: &str) -> PEFile {
        let raw_bytes = std::fs::read(path).unwrap();
        let dos_hdr: [u8; 64] = raw_bytes[0..MS_DOS_HEADER_SIZE].try_into().expect("Slice has incorrect length");
        let sig_off           = dos_hdr[PE_SIGNATURE_POINTER_OFFSET] as usize;
        let sig: [u8; 4]      = raw_bytes[sig_off..sig_off + PE_SIGNATURE_SIZE].try_into().expect("Slice has incorrect length");
        let coff_start        = sig_off + PE_SIGNATURE_SIZE;
        let coff_hdr          = CoffHeader::new(&raw_bytes[coff_start..coff_start + MS_DOS_HEADER_SIZE]);
        let opt_hdr_start     = coff_start + COFF_HEADER_SIZE;
        let opt_hdr           = OptionalHeader::new(&raw_bytes[opt_hdr_start..opt_hdr_start + coff_hdr.size_of_optional_header as usize]);

        PEFile {
            path:            path.to_string(),
            signature:       sig,
            ms_dos_stub_hdr: dos_hdr,
            coff_header:     coff_hdr,
            optional_header: opt_hdr,
        }
    }
}
