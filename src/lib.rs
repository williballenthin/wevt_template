use anyhow::{Result};
use log::{debug};

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
