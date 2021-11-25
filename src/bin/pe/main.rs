
mod pe;
mod coff_header;
mod optional_header;

use pe::PEFile;

fn main() {
    let pe = PEFile::new("/mnt/c/Windows/System32/whoami.exe");
    println!("{:#?}", pe);
}
