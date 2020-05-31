use anyhow::{Result};
use log::{debug};
use byteorder::{ByteOrder, LittleEndian};
use crate::pe::PEError::FormatNotSupported;

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

#[derive(Debug)]
struct CRIM {
    signature: u32,
    size: u32,
    major_version: u16,
    minor_version: u16,
    event_providers: Vec<EventProviderDescriptor>,
}

#[derive(Debug)]
struct EventProviderDescriptor {
    guid: uuid::Uuid,
    offset: u32,
}

#[derive(Debug)]
struct WEVT {
    signature: u32,
    size: u32,
    message_table_identifier: Option<u32>,
    element_descriptors: Vec<ElementDescriptor>,
    unk: Vec<u32>,
}

#[derive(Debug)]
struct ElementDescriptor {
    offset: u32,
    unk: u32,
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

    fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        // TODO: bounds check
        buf.copy_from_slice(&self.buf[offset..offset+buf.len()]);
        Ok(())
    }

    fn read_guid(&self, offset: usize) -> Result<uuid::Uuid> {
        let mut guid = [0u8; 16];
        self.read_into(offset + 0, &mut guid);

        // u32be
        guid.swap(0, 3);
        guid.swap(1, 2);
        // u16be
        guid.swap(4, 5);
        // u16be
        guid.swap(6, 7);

        guid: uuid::Builder::from_bytes(guid).build()
    }
}

impl CRIM {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<CRIM> {
        let event_provider_count = tmpl.read_u32(offset + 12)?;
        let mut event_providers = vec![];

        for i in 0..event_provider_count {
            let descriptor = EventProviderDescriptor::read(tmpl, offset + 16 + (20 * i as usize))?;
            event_providers.push(descriptor);
        }

        Ok(CRIM {
            signature: tmpl.read_u32(offset + 0)?,
            size: tmpl.read_u32(offset + 4)?,
            major_version: tmpl.read_u16(offset + 8)?,
            minor_version: tmpl.read_u16(offset + 10)?,
            // event_provider_count, offset + 12
            event_providers,  // offset + 16
        })
    }
}

impl EventProviderDescriptor {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<EventProviderDescriptor> {
        Ok(EventProviderDescriptor {
            guid: tmpl.read_guid(offset + 0)?,
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
            // element_descriptor_count,  offset + 12
            // unk_count, offset + 16
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
        let mut signature = [0u8; 4];
        tmpl.read_into(self.offset as usize, &mut signature)?;

        match &signature[..] {
            b"CHAN" => Ok(Element::CHAN(CHAN::read(tmpl, self.offset as usize)?)),
            _ => todo!(),
        }
    }
}

#[derive(Debug)]
struct KEYW {}
#[derive(Debug)]
struct LEVL {}
#[derive(Debug)]
struct MAPS {}
#[derive(Debug)]
struct BMAP {}
#[derive(Debug)]
struct VMAP {}

#[derive(Debug)]
struct ChannelDefinition {
    identifier: u32,
    offset: u32,
    message_table_identifier: Option<u32>,
}

impl ChannelDefinition {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<ChannelDefinition> {
        let message_table_identifier = match tmpl.read_u32(offset + 12)? {
            0xFFFFFFFF => None,
            id @ 0 ..= 0xFFFFFFFE => Some(id),
        };

        Ok(ChannelDefinition {
            identifier: tmpl.read_u32(offset + 0)?,
            offset: tmpl.read_u32(offset + 4)?,
            message_table_identifier,
        })
    }

    fn data(&self, tmpl: &WevtTemplate) -> Result<ChannelData> {
        ChannelData::read(tmpl, self.offset as usize)
    }
}

#[derive(Debug)]
struct ChannelData {
    value: Vec<u8>,
}

impl ChannelData {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<ChannelData> {
        let size = tmpl.read_u32(offset + 0)?;
        let value = tmpl.read_buf(offset + 4, size as usize - 4)?;
        Ok(ChannelData { value })
    }

    fn string(&self) -> Result<String> {
        let chars: Vec<u16> = self.value
            .chunks_exact(2)
            .map(|buf| LittleEndian::read_u16(buf))
            .collect();

        widestring::U16String::from_vec(chars).to_string().map_err(|e| e.into())
    }
}

#[derive(Debug)]
struct CHAN {
    signature: u32,
    size: u32,
    channel_definitions: Vec<ChannelDefinition>,
}

impl CHAN {
    fn read(tmpl: &WevtTemplate, offset: usize) -> Result<CHAN> {
        let channel_definition_count = tmpl.read_u32(offset + 8)?;
        let mut channel_definitions= vec![];
        for i in 0..channel_definition_count {
            channel_definitions.push(ChannelDefinition::read(tmpl, offset + 12 + (16 * i as usize))?);
        }

        Ok(CHAN {
            signature: tmpl.read_u32(offset + 0)?,
            size: tmpl.read_u32(offset + 4)?,
            channel_definitions,
        })
    }
}

#[derive(Debug)]
struct EVTN {}
#[derive(Debug)]
struct OPCO {}
#[derive(Debug)]
struct TASK {}
#[derive(Debug)]
struct TTBL {}
#[derive(Debug)]
struct TEMP {}

#[derive(Debug)]
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
                debug!("\n{}", util::hexdump(&buf[..0x400], 0x0));

                let tmpl = WevtTemplate{langid, buf};
                let crim = CRIM::read(&tmpl, 0x0)?;
                debug!("crim: {:#x?}", crim);

                for (i, event_provider_ref) in crim.event_providers.iter().enumerate() {
                    let event_provider = crim.event_providers[0].event_provider(&tmpl)?;
                    debug!("event_provider[{}]: {:#x?}", i, event_provider);

                    for (j, elem_ref) in event_provider.element_descriptors.iter().enumerate() {
                        let elem = elem_ref.element(&tmpl)?;
                        debug!("element[{}]: {:#x?}", j, elem);

                        if let Element::CHAN(chan) = elem {
                            let cd = &chan.channel_definitions[0];
                            let data = cd.data(&tmpl)?;

                            debug!("defintions.data: {:#x?}", data.string()?);
                        }
                    }
                }

                ret.push(tmpl);
            },
            _ => continue,
        }
    }

    Ok(ret)
}
