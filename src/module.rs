use bitflags::bitflags;
use anyhow::Result;
use thiserror::Error;
use byteorder::{ByteOrder, LittleEndian};

use crate::{VA, RVA, pagemap::PageMap, pagemap::PageMapError};

#[derive(Error, Debug)]
pub enum ModuleError {
    #[error("invalid address: {0:#x}")]
    InvalidAddress(u64),
}

#[derive(Copy, Clone)]
pub enum Arch {
    X32,
    X64,
}

impl Arch {
    pub fn pointer_size(&self) -> usize {
        match self {
            Arch::X32 => 4,
            Arch::X64 => 8,
        }
    }
}

bitflags! {
    pub struct Permissions: u8 {
        const R = 0b0000_0001;
        const W = 0b0000_0010;
        const X = 0b0000_0100;
        const RW = Self::R.bits | Self::W.bits;
        const RX =  Self::R.bits | Self::X.bits;
        const WX =  Self::W.bits | Self::X.bits;
        const RWX =  Self::R.bits | Self::W.bits | Self::X.bits;
    }
}

#[derive(Debug)]
pub struct Section {
    // source data, from the PE file
    pub physical_range: std::ops::Range<RVA>,
    // as mapped into memory
    pub virtual_range: std::ops::Range<RVA>,
    pub perms: Permissions,
    pub name:  String,
}

/// An address space, as a file would be loaded into memory.
/// This has an associated architecture (e.g. x32 or x64),
/// base address, and collection of sections.
/// This is the information that we'd expect to be common across
/// plTODOTODOTODO
/// TODO
pub struct Module {
    pub arch:          Arch,
    pub base_address:  VA,
    pub sections:      Vec<Section>,
    pub address_space: PageMap<u8>,
}

impl Module {
    pub fn with_rva(&self) -> RelativeAddressSpace {
        RelativeAddressSpace{
            m: self
        }
    }

    pub fn with_va(&self) -> AbsoluteAddressSpace {
        AbsoluteAddressSpace{
            m: self
        }
    }
}

pub struct RelativeAddressSpace<'a> {
    m: &'a Module
}

impl<'a> RelativeAddressSpace<'a> {
    pub fn read_bytes(&self, rva: RVA, length: usize) -> Result<Vec<u8>> {
        self.m
            .address_space
            .slice(rva, rva + length as u64)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
    }

    pub fn read_bytes_into<'b>(&self, rva: RVA, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        self.m
            .address_space
            .slice_into(rva, buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(Ok)
    }

    pub fn read_u8(&self, rva: RVA) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.m
            .address_space
            .slice_into(rva, &mut buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(|buf| Ok(buf[0]))
    }

    pub fn read_u16(&self, rva: RVA) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.m
            .address_space
            .slice_into(rva, &mut buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(|buf| Ok(LittleEndian::read_u16(buf)))
    }

    pub fn read_u32(&self, rva: RVA) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.m
            .address_space
            .slice_into(rva, &mut buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(|buf| Ok(LittleEndian::read_u32(buf)))
    }

    pub fn read_u64(&self, rva: RVA) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.m
            .address_space
            .slice_into(rva, &mut buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(|buf| Ok(LittleEndian::read_u64(buf)))
    }

    pub fn read_i32(&self, rva: RVA) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.m
            .address_space
            .slice_into(rva, &mut buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(|buf| Ok(LittleEndian::read_i32(buf)))
    }

    pub fn read_i64(&self, rva: RVA) -> Result<i64> {
        let mut buf = [0u8; 8];
        self.m
            .address_space
            .slice_into(rva, &mut buf)
            .map_err(|_| ModuleError::InvalidAddress(rva).into())
            .and_then(|buf| Ok(LittleEndian::read_i64(buf)))
    }

    /// Read a VA from the given RVA.
    /// Note that the size of the read is dependent on the architecture.
    pub fn read_va(&self, rva: RVA) -> Result<VA> {
        match self.m.arch {
            Arch::X32 => Ok(self.read_u32(rva)? as u64),
            Arch::X64 => Ok(self.read_u64(rva)? as u64),
        }
    }

    /// Read a VA from the given RVA.
    /// Note that the size of the read is dependent on the architecture.
    /// Note that the RVA must be *positive*. This won't read negative RVAs.
    pub fn read_rva(&self, rva: RVA) -> Result<RVA> {
        match self.m.arch {
            Arch::X32 => Ok(self.read_u32(rva)? as u64),
            Arch::X64 => Ok(self.read_u64(rva)? as u64),
        }
    }
}

pub struct AbsoluteAddressSpace<'a> {
    m: &'a Module
}

impl<'a> AbsoluteAddressSpace<'a> {
    pub fn read_bytes(&self, va: VA, length: usize) -> Result<Vec<u8>> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_bytes(va - self.m.base_address, length)
    }

    pub fn read_bytes_into<'b>(&self, va: VA, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_bytes_into(va - self.m.base_address, buf)
    }

    pub fn read_u8(&self, va: VA) -> Result<u8> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_u8(va - self.m.base_address)
    }

    pub fn read_u16(&self, va: VA) -> Result<u16> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_u16(va - self.m.base_address)
    }

    pub fn read_u32(&self, va: VA) -> Result<u32> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_u32(va - self.m.base_address)
    }

    pub fn read_u64(&self, va: VA) -> Result<u64> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_u64(va - self.m.base_address)
    }

    pub fn read_i32(&self, va: VA) -> Result<i32> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_i32(va - self.m.base_address)
    }

    pub fn read_i64(&self, va: VA) -> Result<i64> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_i64(va - self.m.base_address)
    }

    /// Read a VA from the given VA.
    /// Note that the size of the read is dependent on the architecture.
    /// Note that the RVA must be *positive*. This won't read negative RVAs.
    pub fn read_rva(&self, va: VA) -> Result<RVA> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_rva(va - self.m.base_address)
    }

    /// Read a VA from the given VA.
    /// Note that the size of the read is dependent on the architecture.
    pub fn read_va(&self, va: VA) -> Result<VA> {
        if va < self.m.base_address {
            return Err(PageMapError::NotMapped.into());
        }
        self.m.with_rva().read_va(va - self.m.base_address)
    }
}