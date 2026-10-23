//! helpers.rs - helper functions for Laboratory 2 (PE header parser).
//!
//! You do NOT need to modify this file. It gives you:
//!   - load_file()                  read a whole file into memory
//!   - read_u8/u16/u32/u64()        read little-endian integers at a file offset
//!   - read_bytes()                 read a range of raw bytes
//!   - read_fixed_string()          read a fixed-size, maybe NUL-padded string (section names)
//!   - read_cstring()               read a NUL-terminated string (bonus: imports/exports)
//!   - hex()                        format a number as "0x0000ABCD"
//!   - format_unix_timestamp()      format a TimeDateStamp as "2020-09-13 12:26:40 UTC"
//!   - decode_flags()               turn a bit mask into "FLAG_A | FLAG_B"
//!
//! Every read is bounds-checked and returns a `Result`: reading outside the file gives an
//! `Err(ParseError)` instead of a panic. Use the `?` operator to pass errors up:
//!     let e_lfanew = read_u32(data, 0x3C)?;
//! Create your own errors with:
//!     return Err(ParseError::new("invalid PE signature"));

#![allow(dead_code)]

use std::fmt;

/// The error type used by every helper (and by your parser).
#[derive(Debug)]
pub struct ParseError(pub String);

impl ParseError {
    pub fn new(message: impl Into<String>) -> Self {
        ParseError(message.into())
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Shorter name for `Result<T, ParseError>`.
pub type Result<T> = std::result::Result<T, ParseError>;

/// Formats a number in hexadecimal, padded to `width` digits: `hex(0x4C, 4) == "0x004C"`.
pub fn hex(value: u64, width: usize) -> String {
    format!("0x{:0width$X}", value, width = width)
}

/// Reads the whole file into memory.
pub fn load_file(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| ParseError::new(format!("cannot open file '{}': {}", path, e)))
}

/// Reads `count` bytes starting at `offset`.
pub fn read_bytes(data: &[u8], offset: u64, count: u64) -> Result<&[u8]> {
    let size = data.len() as u64;
    if offset > size || count > size - offset {
        return Err(ParseError::new(format!(
            "read of {} byte(s) at offset {} is outside the file (file size is {})",
            count,
            hex(offset, 8),
            hex(size, 8)
        )));
    }
    Ok(&data[offset as usize..(offset + count) as usize])
}

/// Reads an unsigned little-endian integer of `size` bytes (used by the read_uXX functions below).
fn read_le(data: &[u8], offset: u64, size: u64) -> Result<u64> {
    let bytes = read_bytes(data, offset, size)?;
    Ok(bytes.iter().rev().fold(0u64, |value, &b| (value << 8) | b as u64))
}

pub fn read_u8(data: &[u8], offset: u64) -> Result<u8> {
    Ok(read_le(data, offset, 1)? as u8)
}

pub fn read_u16(data: &[u8], offset: u64) -> Result<u16> {
    Ok(read_le(data, offset, 2)? as u16)
}

pub fn read_u32(data: &[u8], offset: u64) -> Result<u32> {
    Ok(read_le(data, offset, 4)? as u32)
}

pub fn read_u64(data: &[u8], offset: u64) -> Result<u64> {
    read_le(data, offset, 8)
}

/// Reads a fixed-size text field (e.g. the 8-byte section Name). Stops at the first NUL byte,
/// but the field does not have to contain one: ".textbss" uses all 8 bytes.
pub fn read_fixed_string(data: &[u8], offset: u64, length: u64) -> Result<String> {
    let raw = read_bytes(data, offset, length)?;
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// Reads a NUL-terminated string (e.g. DLL or function names, for the bonus tasks).
pub fn read_cstring(data: &[u8], offset: u64, max_length: u64) -> Result<String> {
    let mut raw = Vec::new();
    for i in 0..max_length {
        let c = read_u8(data, offset + i)?;
        if c == 0 {
            return Ok(String::from_utf8_lossy(&raw).into_owned());
        }
        raw.push(c);
    }
    Err(ParseError::new(format!(
        "string at {} is longer than {} bytes",
        hex(offset, 8),
        max_length
    )))
}

/// Converts a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) to "YYYY-MM-DD hh:mm:ss UTC".
pub fn format_unix_timestamp(timestamp: u32) -> String {
    // Civil-from-days algorithm (Howard Hinnant); no external crates needed.
    let seconds = timestamp as i64 % 86400;
    let days = timestamp as i64 / 86400 + 719468;
    let era = days / 146097;
    let day_of_era = days - era * 146097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year,
        month,
        day,
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Splits `value` into the flags from `table`:
/// `decode_flags(0x22, TABLE) == "EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE"`.
/// Bits that are not in the table are shown in hex at the end, so nothing is silently lost.
pub fn decode_flags(value: u64, table: &[(u64, &str)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut remaining = value;
    for &(bit, name) in table {
        if bit != 0 && value & bit == bit {
            parts.push(name.to_string());
            remaining &= !bit;
        }
    }
    if remaining != 0 {
        parts.push(hex(remaining, 1));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" | ")
    }
}
