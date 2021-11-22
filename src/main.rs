mod elf;
mod program_header;
mod section_header;

use elf::ElfFile;

fn main() {
    let elf = ElfFile::new("/usr/bin/ls");
    println!("{}", elf);
}
