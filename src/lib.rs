use anyhow::{Result};
use log::{debug};
use byteorder::{ByteOrder, LittleEndian};

pub mod util;
pub mod pagemap;
pub mod module;
pub mod pe;
pub mod rsrc;

type VA = u64;
type RVA = u64;

pub struct WevtTemplate {
    pub langid: u32,
    buf: Vec<u8>,
}

struct CRIM {
    signature: u32,
    size: u32,
    major_version: u16,
    minor_version: u16,
    // TODO: remove these `count` fields, since they're implicit the array
    event_provider_count: u32,
    event_providers: Vec<EventProviderDescriptor>,
}

struct EventProviderDescriptor {
    guid: Vec<u8>,  // TODO: [u8; 16]
    offset: u32,
}

struct WEVT {
    signature: u32,
    size: u32,
    message_table_identifier: Option<u32>,
    element_descriptor_count: u32,
    unk_count: u32,
    element_descriptors: Vec<ElementDescriptor>,
    unk: Vec<u32>,
}

struct ElementDescriptor {
    offset: u32,
    unk: u32,
}

struct KEYW {}
struct LEVL {}
struct MAPS {}
struct BMAP {}
struct VMAP {}
struct CHAN {}
struct EVTN {}
struct OPCO {}
struct TASK {}
struct TTBL {}
struct TEMP {}

enum Element {
    KEYW(KEYW),
    LEVL(LEVL),
    MAPS(MAPS),
    BMAP(BMAP),
    VMAP(VMAP),
    CHAN(CHAN),
    EVTN(EVTN),
    OPCO(OPCO),
    TASK(TASK),
    TTBL(TTBL),
    TEMP(TEMP),
}

impl WevtTemplate {
    fn read_u16(&self, offset: usize) -> Result<u16> {
        // TODO: bounds check
        let buf = &self.buf[offset..offset+2];
        Ok(LittleEndian::read_u16(buf))
    }

    fn read_u32(&self, offset: usize) -> Result<u32> {
        // TODO: bounds check
        let buf = &self.buf[offset..offset+4];
        Ok(LittleEndian::read_u32(buf))
    }

    fn read_buf(&self, offset: usize, length: usize) -> Result<Vec<u8>> {
        // TODO: bounds check
        Ok(self.buf[offset..offset+length].to_vec())
    }
}

impl CRIM {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<CRIM> {
        let event_provider_count = tmpl.read_u32(offset + 14)?;
        let mut event_providers = vec![];

        let mut offset = offset + 0x18;
        for _ in 0..event_provider_count {
            event_providers.push(EventProviderDescriptor::read(tmpl, offset)?);
            offset += 0x20;
        }

        Ok(CRIM {
            signature: tmpl.read_u32(offset + 0)?,
            size: tmpl.read_u32(offset + 4)?,
            major_version: tmpl.read_u16(offset + 8)?,
            minor_version: tmpl.read_u16(offset + 10)?,
            event_provider_count, // offset + 14
            event_providers,  // offset + 18
        })
    }
}

impl EventProviderDescriptor {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<EventProviderDescriptor> {
        Ok(EventProviderDescriptor {
            guid: tmpl.read_buf(offset + 0, 16)?,
            offset: tmpl.read_u32(offset + 16)?,
        })
    }

    fn event_provider(&self, tmpl: &WevtTemplate) -> Result<WEVT> {
        WEVT::read(tmpl, self.offset as usize)
    }
}

impl WEVT {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<WEVT> {
        let message_table_identifier = match tmpl.read_u32(offset + 8)? {
            0xFFFFFFFF => None,
            id @ 0 ..= 0xFFFFFFFE => Some(id),
        };

        let element_descriptor_count = tmpl.read_u32(offset + 12)?;
        let mut element_descriptors = vec![];
        for i in 0..element_descriptor_count {
            element_descriptors.push(ElementDescriptor::read(tmpl, offset + 20 + (8 * i as usize))?);
        }

        Ok(WEVT {
            signature: tmpl.read_u32(offset + 0)?,
            size: tmpl.read_u32(offset + 4)?,
            message_table_identifier,  // offset + 8
            element_descriptor_count,  // offset + 12
            unk_count: tmpl.read_u32(offset + 16)?,
            element_descriptors,      // offset + 20
            unk: vec![],              // offset + varies
        })
    }
}


impl ElementDescriptor {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<ElementDescriptor> {
        Ok(ElementDescriptor {
            offset: tmpl.read_u32(offset + 0)?,
            unk: tmpl.read_u32(offset + 4)?,
        })
    }

    fn element(&self, tmpl: &WevtTemplate) -> Result<Element> {
        todo!()
    }
}

pub fn get_wevt_templates(pe: &pe::PE) -> Result<Vec<WevtTemplate>> {
    // found at .rsrc node path:  "WEVT_TEMPLATE" / 0x1 / ${langid}

    let mut ret = vec![];

    let rsrc = match rsrc::ResourceSectionData::from_pe(pe)? {
        None => return Ok(vec![]),
        Some(rsrc) => rsrc,
    };

    let wevt_template_node = match rsrc.root()?.get_child_by_name(&rsrc, "WEVT_TEMPLATE")? {
        Some(rsrc::NodeChild::Node(node)) => node,
        _ => return Ok(vec![]),
    };

    let one_node = match wevt_template_node.get_child_by_id(&rsrc, 1)? {
        Some(rsrc::NodeChild::Node(node)) => node,
        _ => return Ok(vec![]),
    };

    for (lang, lang_node) in one_node.children(&rsrc)?.iter() {
        match (lang.id(&rsrc)?, lang_node) {
            (rsrc::NodeIdentifier::ID(langid), rsrc::NodeChild::Data(descriptor)) => {
                debug!("WEVT_TEMPLATE: lang: {:} offset: {:#x} size: {:#x}", langid, descriptor.rva, descriptor.size);
                let buf = descriptor.data(&pe)?;
                ret.push(WevtTemplate{langid, buf});
            },
            _ => continue,
        }
    }

    Ok(ret)
}
