//! Laboratory 2 - PE header parser (starter kit)
//!
//! Run: cargo run -- <file.exe>
//!
//! Every place you have to write code is marked with TODO. Work top to bottom: the program walks
//! the file step by step (see run() at the end) and prints each header as soon as it is parsed,
//! so you can test after every function you finish. An unfinished function stops the program
//! with "error: TODO: ...".
//!
//! All the offsets you need are in the tables on the lab page.

// Silences warnings about unused parameters in the TODO stubs; remove it once you are done.
#![allow(unused_variables, unused_mut, dead_code, unreachable_code)]

mod helpers;

use helpers::*;

// =============================================================================================
// Data structures: what we keep from each header (already complete)
// =============================================================================================

struct DosHeader {
    e_magic: u16,
    e_lfanew: u32,
}

/// a.k.a. COFF header
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

struct DataDirectory {
    rva: u32,
    size: u32,
}

struct OptionalHeader {
    magic: u16,
    is_pe32_plus: bool, // true for 64-bit files (Magic == 0x20B)
    address_of_entry_point: u32,
    image_base: u64, // 4 bytes in PE32, 8 bytes in PE32+
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
    subsystem: u16,
    dll_characteristics: u16,
    number_of_rva_and_sizes: u32,
    data_directories: Vec<DataDirectory>,
}

struct Section {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
}

struct PeFile {
    dos: DosHeader,
    file: FileHeader,
    optional: OptionalHeader,
    sections: Vec<Section>,
}

// =============================================================================================
// Lookup tables
// =============================================================================================

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        _ => "unknown",
    }
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows console",
        _ => "unknown",
    }
}

fn data_directory_name(index: usize) -> &'static str {
    // TODO: complete the list of the 16 data directory names (see the lab page)
    const NAMES: [&str; 16] = [
        "Export", "Import", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?",
    ];
    NAMES.get(index).copied().unwrap_or("?")
}

// TODO: complete both flag tables (see the lab page). decode_flags() shows unknown bits in hex.
const FILE_CHARACTERISTICS: &[(u64, &str)] = &[
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
];

const DLL_CHARACTERISTICS: &[(u64, &str)] = &[
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
];

/// Returns "R-X", "RW-", ... from the IMAGE_SCN_MEM_READ (0x40000000), IMAGE_SCN_MEM_WRITE (0x80000000)
/// and IMAGE_SCN_MEM_EXECUTE (0x20000000) bits of a section's Characteristics.
fn section_permissions(characteristics: u32) -> String {
    let r = if characteristics & 0x4000_0000 != 0 { 'R' } else { '-' };
    let w = '-'; // TODO
    let x = '-'; // TODO
    format!("{}{}{}", r, w, x)
}

// =============================================================================================
// Parsing
// =============================================================================================

/// Worked example: read the fields you need with the read_uXX helpers and validate what you can.
fn parse_dos_header(data: &[u8]) -> Result<DosHeader> {
    let e_magic = read_u16(data, 0x00)?;
    if e_magic != 0x5A4D {
        // "MZ"
        return Err(ParseError::new(format!(
            "not a PE file: missing \"MZ\" signature (found {})",
            hex(e_magic as u64, 4)
        )));
    }
    let e_lfanew = read_u32(data, 0x3C)?;
    Ok(DosHeader { e_magic, e_lfanew })
}

/// Reads the 4-byte signature at `offset` and returns an error if it is not "PE\0\0" (0x00004550).
fn check_pe_signature(data: &[u8], offset: u64) -> Result<()> {
    let pe_sig = read_u32(data, offset)?;
    if pe_sig != 0x4550 {  // PE\0\0
        return Err(ParseError::new(format!{
            "PE signature different: {}", hex(pe_sig as u64, 4)
        }))
    }
    Ok(())
    // Err(ParseError::new("TODO: implement check_pe_signature()"))
}

/// `offset` is where the COFF file header starts (right after the signature).
fn parse_file_header(data: &[u8], offset: u64) -> Result<FileHeader> {

    let machine = read_u16(data, offset)?;
    let number_of_sections = read_u16(data, offset + 2)?;
    let time_date_stamp = read_u32(data, offset + 4)?;
    let size_of_optional_header = read_u16(data, offset + 16)?;
    let characteristics = read_u16(data, offset + 18)?;

    Ok(FileHeader {
        machine,
        number_of_sections,
        time_date_stamp,
        size_of_optional_header,
        characteristics
    })
}

/// Reads `count` entries of 8 bytes each: { u32 VirtualAddress (RVA); u32 Size; }
fn parse_data_directories(data: &[u8], offset: u64, count: u32) -> Result<Vec<DataDirectory>> {
    let mut directories: Vec<DataDirectory> = Vec::new();
    // TODO
    Err(ParseError::new("TODO: implement parse_data_directories()"))
}

/// `offset` is where the optional header starts. Remember: some offsets differ between PE32 and PE32+.
fn parse_optional_header(data: &[u8], offset: u64, size_of_optional_header: u16) -> Result<OptionalHeader> {
    // TODO:
    //   1. read Magic; return an error if it is neither 0x10B (PE32) nor 0x20B (PE32+)
    let magic = read_u16(data, offset)?;
    if magic != 0x10B && magic != 0x20B {
        return Err(ParseError::new(format!("magic not PE32(+): {}", hex(magic as u64, 4))))
    }

    

    //   2. read the other fields, using the right offsets for PE32 / PE32+
    //   3. never trust NumberOfRvaAndSizes: parse at most 16 data directories
    //   4. return an error if size_of_optional_header is too small to hold the data directories
    //   5. data_directories: parse_data_directories(...)?
    Err(ParseError::new("TODO: implement parse_optional_header()"))
}

/// `offset` is where the section table starts; each section header is 40 bytes.
fn parse_sections(data: &[u8], offset: u64, count: u16) -> Result<Vec<Section>> {
    let mut sections: Vec<Section> = Vec::new();
    // TODO: for each section read Name (read_fixed_string, 8 bytes), VirtualSize, VirtualAddress,
    //       SizeOfRawData, PointerToRawData, Characteristics
    Err(ParseError::new("TODO: implement parse_sections()"))
}

// =============================================================================================
// RVA -> file offset
// =============================================================================================

/// Returns the section that contains `rva` once the image is loaded in memory:
/// VirtualAddress <= rva < VirtualAddress + VirtualSize
/// (some linkers write VirtualSize = 0; in that case use SizeOfRawData)
fn find_section(pe: &PeFile, rva: u32) -> Option<&Section> {
    // TODO
    None
}

/// Converts an RVA to a file offset. Returns None if the RVA has no bytes in the file.
///   - rva < SizeOfHeaders              -> the headers are mapped 1:1, offset = rva
///   - find the section containing rva  -> none: return None
///   - delta = rva - VirtualAddress     -> delta >= SizeOfRawData: zero-filled memory, return None
///   - offset = PointerToRawData + delta
fn rva_to_offset(pe: &PeFile, rva: u32) -> Option<u64> {
    // TODO
    None
}

// =============================================================================================
// Printing (PROVIDED, you do not need to change anything below until run())
// =============================================================================================

fn print_field(name: &str, value: &str) {
    println!("  {:<22}{}", name, value);
}

fn print_dos_header(dos: &DosHeader) {
    println!("DOS header");
    print_field("e_magic", &format!("{} (\"MZ\")", hex(dos.e_magic as u64, 4)));
    print_field("e_lfanew", &hex(dos.e_lfanew as u64, 8));
}

fn print_pe_signature(offset: u64) {
    println!("\nPE signature \"PE\\0\\0\" found at {}", hex(offset, 8));
}

fn print_file_header(file: &FileHeader) {
    println!("\nCOFF file header");
    print_field("Machine", &format!("{} ({})", hex(file.machine as u64, 4), machine_name(file.machine)));
    print_field("NumberOfSections", &file.number_of_sections.to_string());
    print_field(
        "TimeDateStamp",
        &format!("{} ({})", hex(file.time_date_stamp as u64, 8), format_unix_timestamp(file.time_date_stamp)),
    );
    print_field("SizeOfOptionalHeader", &hex(file.size_of_optional_header as u64, 4));
    print_field(
        "Characteristics",
        &format!(
            "{} ({})",
            hex(file.characteristics as u64, 4),
            decode_flags(file.characteristics as u64, FILE_CHARACTERISTICS)
        ),
    );
}

fn print_optional_header(opt: &OptionalHeader) {
    println!("\nOptional header");
    let pe_type = if opt.is_pe32_plus { "PE32+" } else { "PE32" };
    print_field("Magic", &format!("{} ({})", hex(opt.magic as u64, 4), pe_type));
    print_field("AddressOfEntryPoint", &hex(opt.address_of_entry_point as u64, 8));
    print_field("ImageBase", &hex(opt.image_base, if opt.is_pe32_plus { 16 } else { 8 }));
    print_field("SectionAlignment", &hex(opt.section_alignment as u64, 8));
    print_field("FileAlignment", &hex(opt.file_alignment as u64, 8));
    print_field("SizeOfImage", &hex(opt.size_of_image as u64, 8));
    print_field("SizeOfHeaders", &hex(opt.size_of_headers as u64, 8));
    print_field("Subsystem", &format!("{} ({})", opt.subsystem, subsystem_name(opt.subsystem)));
    print_field(
        "DllCharacteristics",
        &format!(
            "{} ({})",
            hex(opt.dll_characteristics as u64, 4),
            decode_flags(opt.dll_characteristics as u64, DLL_CHARACTERISTICS)
        ),
    );
    print_field("NumberOfRvaAndSizes", &opt.number_of_rva_and_sizes.to_string());

    println!("\nData directories");
    println!("  {:<3} {:<13} {:<11} {}", "#", "Name", "RVA", "Size");
    for (i, dir) in opt.data_directories.iter().enumerate() {
        println!(
            "  {:<3} {:<13} {:<11} {}",
            i,
            data_directory_name(i),
            hex(dir.rva as u64, 8),
            hex(dir.size as u64, 8)
        );
    }
}

fn print_sections(sections: &[Section]) {
    println!("\nSections");
    println!(
        "  {:<3} {:<9} {:<11} {:<11} {:<11} {:<11} {:<11} {}",
        "#", "Name", "VirtAddr", "VirtSize", "RawPtr", "RawSize", "Flags", "Perm"
    );
    for (i, s) in sections.iter().enumerate() {
        println!(
            "  {:<3} {:<9} {:<11} {:<11} {:<11} {:<11} {:<11} {}",
            i,
            s.name,
            hex(s.virtual_address as u64, 8),
            hex(s.virtual_size as u64, 8),
            hex(s.pointer_to_raw_data as u64, 8),
            hex(s.size_of_raw_data as u64, 8),
            hex(s.characteristics as u64, 8),
            section_permissions(s.characteristics)
        );
    }
}

fn print_entry_point(pe: &PeFile) {
    let opt = &pe.optional;
    let ep = opt.address_of_entry_point;
    println!("\nEntry point");
    if ep == 0 {
        print_field("RVA", "0 (no entry point)");
        return;
    }
    let location = if ep < opt.size_of_headers {
        "headers".to_string()
    } else {
        match find_section(pe, ep) {
            Some(s) => s.name.clone(),
            None => "outside every section".to_string(),
        }
    };
    print_field("RVA", &hex(ep as u64, 8));
    print_field("VA", &hex(opt.image_base.wrapping_add(ep as u64), if opt.is_pe32_plus { 16 } else { 8 }));
    print_field("Section", &location);
    match rva_to_offset(pe, ep) {
        Some(offset) => print_field("File offset", &hex(offset, 8)),
        None => print_field("File offset", "none (not backed by file data)"),
    }
}

// =============================================================================================
// Walking the file
// =============================================================================================

fn run(path: &str) -> Result<()> {
    let data = load_file(path)?;
    println!("File: {} ({} bytes)\n", path, data.len());

    // Step 1: DOS header ("MZ" and e_lfanew) at file offset 0.
    let dos = parse_dos_header(&data)?;
    print_dos_header(&dos);

    // Step 2: the "PE\0\0" signature is at e_lfanew.
    let pe_offset = dos.e_lfanew as u64;
    check_pe_signature(&data, pe_offset)?;
    print_pe_signature(pe_offset);

    // Step 3: the COFF file header follows the 4-byte signature.
    let file_header_offset: u64 = pe_offset + 4;
    let file = parse_file_header(&data, file_header_offset)?;
    print_file_header(&file);

    // Step 4: the optional header follows the 20-byte COFF file header.
    let optional_header_offset: u64 = pe_offset + 24;
    let optional = parse_optional_header(&data, optional_header_offset, file.size_of_optional_header)?;
    print_optional_header(&optional);

    // Step 5: the section table follows the optional header (SizeOfOptionalHeader bytes).
    let section_table_offset: u64 = 0; // TODO
    let sections = parse_sections(&data, section_table_offset, file.number_of_sections)?;
    print_sections(&sections);

    // Step 6: where does execution start? (uses find_section and rva_to_offset)
    let pe = PeFile { dos, file, optional, sections };
    print_entry_point(&pe);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} <file>", args[0]);
        std::process::exit(2);
    }
    if let Err(e) = run(&args[1]) {
        eprintln!("\nerror: {}", e);
        std::process::exit(1);
    }
}
