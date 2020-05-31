use log::debug;
use thiserror::Error;
use anyhow::Result;

use crate::{VA};
use crate::module::{Module, Section, Permissions, Arch};
use crate::pagemap::PageMap;
use crate::util;


#[derive(Error, Debug)]
pub enum PEError {
    #[error("format not supported: {0}")]
    FormatNotSupported(String),

    #[error("malformed PE file: {0}")]
    MalformedPEFile(String),
}

/// A parsed and loaded PE file.
/// The `pe` field contains the parsed data, courtesy of goblin.
/// The `module` field contains an address space as the PE would be loaded.
pub struct PE<'a> {
    pub pe: goblin::pe::PE<'a>,
    pub module: Module,
}

impl<'a> PE<'a> {
    pub fn get_pe_executable_sections(&self) -> Result<Vec<std::ops::Range<VA>>> {
        let image_base = self
            .pe
            .header
            .optional_header
            .ok_or_else(|| PEError::MalformedPEFile("no optional header".to_string()))?
            .windows_fields
            .image_base;

        Ok(self
            .pe
            .sections
            .iter()
            .filter(|section| section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE > 0)
            .map(|section| std::ops::Range{
                start: (image_base + section.virtual_address as u64) as VA,
                end: (image_base + section.virtual_address as u64 + section.virtual_size as u64) as VA,
            })
            .collect())
    }
}

fn get_pe(buf: &[u8]) -> Result<goblin::pe::PE> {
    match goblin::Object::parse(buf)? {
        goblin::Object::PE(pe) => return Ok(pe),
        goblin::Object::Elf(_) => return Err(PEError::FormatNotSupported("elf".to_string()).into()),
        goblin::Object::Archive(_) => return Err(PEError::FormatNotSupported("archive".to_string()).into()),
        goblin::Object::Mach(_) => return Err(PEError::FormatNotSupported("macho".to_string()).into()),
        goblin::Object::Unknown(_) => return Err(PEError::FormatNotSupported("unknown".to_string()).into()),
    }
}

fn load_pe_header(buf: &[u8], pe: &goblin::pe::PE) -> Result<Section> {
    let hdr_raw_size = match pe.header.optional_header {
        Some(opt) => opt.windows_fields.size_of_headers,
        // assumption: header is at most 0x200 bytes.
        _ => 0x200,
    };

    //   on disk:
    //
    //   +---------------------------------+
    //   |   header        |  sections...  |
    //   +---------------------------------+
    //   .                  \
    //   .  in memory:       \
    //   .                    \
    //   +-----------------+---+        +-------------
    //   |   header        |   |        |  sections...
    //   +-----------------+---+        +-------------
    //                     ^   ^
    //                     |   +--- virtual size
    //                     |        aligned to 0x200
    //                     +-- raw size
    //                         no alignment

    let hdr_raw_size = std::cmp::min(hdr_raw_size as usize, buf.len());
    let hdr_virt_size = util::align(hdr_raw_size as u64, 0x200);

    Ok(Section {
        physical_range: std::ops::Range {
            start: 0x0,
            end: hdr_raw_size as u64,
        },
        virtual_range: std::ops::Range {
            start: 0x0,
            end: hdr_virt_size,
        },
        perms: Permissions::R,
        name: "header".to_string(),
    })
}

/// The section can be executed as code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// The section can be read.
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// The section can be written to.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn load_pe_section(section: &goblin::pe::section_table::SectionTable) -> Result<Section> {
    let name = String::from_utf8_lossy(&section.name[..])
        .into_owned()
        .trim_end_matches('\u{0}')
        .trim_end()
        .splitn(2, '\u{0}')
        .next()
        .unwrap()
        .to_string();

    let virtual_size = util::align(section.virtual_size as u64, 0x200);

    let mut perms = Permissions::empty();
    if section.characteristics & IMAGE_SCN_MEM_READ > 0 {
        perms.insert(Permissions::R);
    }
    if section.characteristics & IMAGE_SCN_MEM_WRITE > 0 {
        perms.insert(Permissions::W);
    }
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE > 0 {
        perms.insert(Permissions::X);
    }

    Ok(Section {
        physical_range: std::ops::Range {
            start: section.pointer_to_raw_data as u64,
            end: (section.pointer_to_raw_data + section.size_of_raw_data) as u64,
        },
        virtual_range: std::ops::Range{
            start: section.virtual_address as u64,
            end: section.virtual_address as u64 + virtual_size,
        },
        perms,
        name,
    })
}

pub fn load_pe(buf: &[u8]) -> Result<PE> {
    let pe = get_pe(buf)?;

    let arch = match pe.is_64 {
        false => Arch::X32,
        true => Arch::X64,
    };

    let base_address = match pe.header.optional_header {
        Some(opt) => opt.windows_fields.image_base,
        _ => {
            debug!("using default base address: 0x40:000");
            0x40_000
        }
    };

    let mut sections = vec![load_pe_header(buf, &pe)?];
    for section in pe.sections.iter() {
        sections.push(load_pe_section(section)?);
    }

    let max_address = sections
        .iter()
        .map(|sec| sec.virtual_range.end)
        .max()
        .unwrap();

    let max_page_address = util::align(max_address as u64, 0x1000);
    debug!("data address space capacity: {:#x}", max_page_address);
    let mut address_space: PageMap<u8> = PageMap::with_capacity(max_page_address);

    for section in sections.iter() {
        let secbuf = &buf[section.physical_range.start as usize..section.physical_range.end as usize];
        address_space.writezx(section.virtual_range.start, secbuf)?;
    }

    let module = Module {
        arch,
        base_address,
        sections,
        address_space,
    };

    Ok(PE {
        pe,
        module,
    })
}