//! The binding digests of spec 02, section 7.
//!
//! Each statement has one digest under its own tag over fixed-width fields in
//! a fixed order. The verifier always computes the digest itself, from its own
//! chain constants and the transaction's fields; no function here takes a
//! digest from a prover.

use alloc::vec::Vec;

use crate::hash::{TAG_COIN_REVEAL_BINDING, TAG_DATA_REVEAL_BINDING, TAG_HOLD_BINDING, permutations, tag_bytes, tagged};

/// Protocol version 1 as two bytes.
pub const PROTOCOL_VERSION_1: [u8; 2] = [0x00, 0x01];

/// Statement codes.
pub const STATEMENT_COIN_REVEAL: u8 = 0x01;
pub const STATEMENT_DATA_REVEAL: u8 = 0x02;
pub const STATEMENT_HOLD: u8 = 0x03;
/// The statement version of spec 02.
pub const STATEMENT_VERSION_1: u8 = 0x01;

/// Purpose codes. `0x00` and every other value are rejected.
pub const PURPOSE_SPEND: u8 = 0x01;
pub const PURPOSE_REVEAL: u8 = 0x02;
pub const PURPOSE_REVOKE: u8 = 0x03;
pub const PURPOSE_HOLD: u8 = 0x04;

/// The chain constants a node or verifier holds. They are always the
/// verifier's own values, never constants of this crate and never read from a
/// transaction or a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainParams {
    /// The chain identifier, 8 bytes.
    pub chain_id: [u8; 8],
    /// The protocol version, 2 bytes (`0x0001` for version 1).
    pub version: [u8; 2],
    /// The domain tag: the hash of this chain's genesis block.
    pub domain: [u8; 32],
}

/// One field of a binding layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutField {
    pub name: &'static str,
    pub offset: usize,
    pub width: usize,
}

const fn field(name: &'static str, offset: usize, width: usize) -> LayoutField {
    LayoutField { name, offset, width }
}

/// The coin reveal binding fields (spec 02, section 7).
pub const COIN_REVEAL_LAYOUT: [LayoutField; 15] = [
    field("chain_id", 0, 8),
    field("version", 8, 2),
    field("domain", 10, 32),
    field("statement", 42, 1),
    field("statement_version", 43, 1),
    field("type", 44, 2),
    field("purpose", 46, 1),
    field("root", 47, 32),
    field("marker", 79, 32),
    field("remainder", 111, 32),
    field("recipient", 143, 20),
    field("out", 163, 32),
    field("fee", 195, 32),
    field("rule", 227, 32),
    field("remainder_note", 259, 156),
];

/// The data reveal binding fields.
pub const DATA_REVEAL_LAYOUT: [LayoutField; 12] = [
    field("chain_id", 0, 8),
    field("version", 8, 2),
    field("domain", 10, 32),
    field("statement", 42, 1),
    field("statement_version", 43, 1),
    field("type", 44, 2),
    field("purpose", 46, 1),
    field("root", 47, 32),
    field("marker", 79, 32),
    field("party", 111, 32),
    field("fee", 143, 32),
    field("rule", 175, 32),
];

/// The hold binding fields.
pub const HOLD_LAYOUT: [LayoutField; 11] = [
    field("chain_id", 0, 8),
    field("version", 8, 2),
    field("domain", 10, 32),
    field("statement", 42, 1),
    field("statement_version", 43, 1),
    field("type", 44, 2),
    field("purpose", 46, 1),
    field("root", 47, 32),
    field("marker_set_root", 79, 32),
    field("verifier", 111, 32),
    field("challenge", 143, 32),
];

/// The three bindings, for code that treats them alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    CoinReveal,
    DataReveal,
    Hold,
}

impl Binding {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::CoinReveal => TAG_COIN_REVEAL_BINDING,
            Self::DataReveal => TAG_DATA_REVEAL_BINDING,
            Self::Hold => TAG_HOLD_BINDING,
        }
    }

    pub const fn layout(self) -> &'static [LayoutField] {
        match self {
            Self::CoinReveal => &COIN_REVEAL_LAYOUT,
            Self::DataReveal => &DATA_REVEAL_LAYOUT,
            Self::Hold => &HOLD_LAYOUT,
        }
    }

    /// Bytes after the tag.
    pub const fn fields_len(self) -> usize {
        let layout = self.layout();
        let last = layout[layout.len() - 1];
        last.offset + last.width
    }

    /// Bytes with the tag (its length byte included).
    pub fn input_len(self) -> usize {
        tag_bytes(self.tag()).len() + self.fields_len()
    }

    /// Keccak permutations the digest costs.
    pub fn permutations(self) -> usize {
        permutations(self.input_len())
    }

    /// Offset of a named field. Panics on a name the layout does not have,
    /// which is a bug in this crate.
    pub(crate) fn offset(self, name: &str) -> usize {
        self.field(name).offset
    }

    fn field(self, name: &str) -> LayoutField {
        *self
            .layout()
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no field {name}"))
    }
}

/// Fills the fields of a layout in order; every field must be written once.
pub(crate) struct FieldWriter {
    binding: Binding,
    bytes: Vec<u8>,
    written: Vec<bool>,
}

impl FieldWriter {
    pub(crate) fn new(binding: Binding, params: &ChainParams, statement: u8, type_tag: [u8; 2], purpose: u8) -> Self {
        let mut writer = Self {
            binding,
            bytes: alloc::vec![0; binding.fields_len()],
            written: alloc::vec![false; binding.layout().len()],
        };
        writer
            .put("chain_id", &params.chain_id)
            .put("version", &params.version)
            .put("domain", &params.domain)
            .put("statement", &[statement])
            .put("statement_version", &[STATEMENT_VERSION_1])
            .put("type", &type_tag)
            .put("purpose", &[purpose]);
        writer
    }

    pub(crate) fn put(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let index = self
            .binding
            .layout()
            .iter()
            .position(|f| f.name == name)
            .unwrap_or_else(|| panic!("no field {name}"));
        let f = self.binding.layout()[index];
        assert_eq!(value.len(), f.width, "width of {name}");
        assert!(!self.written[index], "{name} written twice");
        self.bytes[f.offset..f.offset + f.width].copy_from_slice(value);
        self.written[index] = true;
        self
    }

    /// The field bytes, after checking that every field was written.
    pub(crate) fn finish(&self) -> Vec<u8> {
        assert!(self.written.iter().all(|&w| w), "a binding field was left out");
        self.bytes.clone()
    }
}

/// `K(tag, fields)` over the bytes a [`FieldWriter`] produced.
pub(crate) fn digest(binding: Binding, fields: &[u8]) -> [u8; 32] {
    debug_assert_eq!(fields.len(), binding.fields_len());
    tagged(binding.tag(), &[fields])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_are_contiguous() {
        for binding in [Binding::CoinReveal, Binding::DataReveal, Binding::Hold] {
            let mut next = 0;
            for f in binding.layout() {
                assert_eq!(f.offset, next, "{}", f.name);
                next += f.width;
            }
        }
    }
}
