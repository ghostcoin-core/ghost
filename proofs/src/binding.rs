//! The binding digests of spec 02, section 7.
//!
//! Each statement has one digest under its own tag over fixed-width fields in
//! a fixed order. The verifier always computes the digest itself, from its own
//! chain constants and the transaction's fields; no function here takes a
//! digest from a prover.

use alloc::vec::Vec;

use crate::hash::{
    POLICY_ADDRESS_BYTES, TAG_ACTION_BINDING_V1, TAG_COIN_REVEAL_BINDING, TAG_COIN_REVEAL_BINDING_V2,
    TAG_DATA_REVEAL_BINDING, TAG_HOLD_BINDING, TAG_POLICY_REVEAL_BINDING_V1, TAG_PREIMAGE_BINDING_V1, permutations,
    tag_bytes, tagged,
};
use crate::reveal_v2::NOTE_V3_BYTES;

/// Protocol version 1 as two bytes.
pub const PROTOCOL_VERSION_1: [u8; 2] = [0x00, 0x01];
/// Protocol version 2 as two bytes, the version of the ordinary class
/// (spec 10, section 4).
pub const PROTOCOL_VERSION_2: [u8; 2] = [0x00, 0x02];

/// Statement codes.
pub const STATEMENT_COIN_REVEAL: u8 = 0x01;
pub const STATEMENT_DATA_REVEAL: u8 = 0x02;
pub const STATEMENT_HOLD: u8 = 0x03;
/// S4, the policy reveal of the policy class (spec 10, section 5).
pub const STATEMENT_POLICY_REVEAL: u8 = 0x04;
/// `KNOW_ACTION_v1`, the proof of a policy action (spec 10, section 8.2).
pub const STATEMENT_KNOW_ACTION: u8 = 0x05;
/// `KNOW_PREIMAGE_v1`, the statement of the statement checker (spec 10,
/// section 9.2).
pub const STATEMENT_KNOW_PREIMAGE: u8 = 0x06;
/// The statement version of spec 02, and of S4.
pub const STATEMENT_VERSION_1: u8 = 0x01;
/// The statement version of S1 in the ordinary class (spec 10, section 4.3).
pub const STATEMENT_VERSION_2: u8 = 0x02;

/// Purpose codes. `0x00` and every other value are rejected.
pub const PURPOSE_SPEND: u8 = 0x01;
pub const PURPOSE_REVEAL: u8 = 0x02;
pub const PURPOSE_REVOKE: u8 = 0x03;
pub const PURPOSE_HOLD: u8 = 0x04;
/// A policy spend: a coin's value moved to its escrow slot (spec 10, section
/// 5.1).
pub const PURPOSE_POLICY_SPEND: u8 = 0x05;
/// A policy action on an escrow slot (spec 10, section 8.2).
pub const PURPOSE_ACTION: u8 = 0x06;
/// A preimage shown to the statement checker (spec 10, section 9.2).
pub const PURPOSE_PREIMAGE: u8 = 0x07;

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

/// The coin reveal binding of the ordinary class, S1 version 2 (spec 10,
/// section 4.2): the fields of [`COIN_REVEAL_LAYOUT`] without `rule`, with
/// the 380-byte note. 607 bytes; neither rule is a field.
pub const COIN_REVEAL_V2_LAYOUT: [LayoutField; 14] = [
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
    field("remainder_note", 227, NOTE_V3_BYTES),
];

/// The policy reveal binding of the policy class, S4 (spec 10, section 5.1):
/// the opened rule's five public fields and the payout instruction, with no
/// `recipient`, and the 380-byte note. 767 bytes; `override_hash` is not a
/// field.
pub const POLICY_REVEAL_LAYOUT: [LayoutField; 19] = [
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
    field("out", 143, 32),
    field("fee", 175, 32),
    field("policy_address", 207, POLICY_ADDRESS_BYTES),
    field("policy_codehash", 227, 32),
    field("params_hash", 259, 32),
    field("action_tag", 291, 32),
    field("action_salt", 323, 32),
    field("instr", 355, 32),
    field("remainder_note", 387, NOTE_V3_BYTES),
];

/// The binding of `KNOW_ACTION_v1` (spec 10, section 8.2). 273 bytes, 297
/// with the 24-byte tag, three permutations. There is no `type`; the
/// integers `action_nonce` and `expiry` are big-endian.
pub const ACTION_LAYOUT: [LayoutField; 15] = [
    field("chain_id", 0, 8),
    field("version", 8, 2),
    field("domain", 10, 32),
    field("statement", 42, 1),
    field("statement_version", 43, 1),
    field("purpose", 44, 1),
    field("policy_address", 45, POLICY_ADDRESS_BYTES),
    field("marker", 65, 32),
    field("action_nonce", 97, 8),
    field("action_tag", 105, 32),
    field("action_salt", 137, 32),
    field("expected_remaining", 169, 32),
    field("debit", 201, 32),
    field("expiry", 233, 8),
    field("calldata_hash", 241, 32),
];

/// The binding of `KNOW_PREIMAGE_v1` (spec 10, section 9.2). 161 bytes, 187
/// with the 26-byte tag, two permutations. There is no `type`.
pub const PREIMAGE_LAYOUT: [LayoutField; 9] = [
    field("chain_id", 0, 8),
    field("version", 8, 2),
    field("domain", 10, 32),
    field("statement", 42, 1),
    field("statement_version", 43, 1),
    field("purpose", 44, 1),
    field("policy_address", 45, POLICY_ADDRESS_BYTES),
    field("y", 65, 32),
    field("context", 97, 64),
];

/// The data reveal binding fields. `cf` is the content fingerprint of the
/// commitment revealed, public so anyone holding the bytes can check them.
pub const DATA_REVEAL_LAYOUT: [LayoutField; 13] = [
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
    field("cf", 207, 32),
];

/// The hold binding fields. `cf` is the content fingerprint of the
/// commitment held.
pub const HOLD_LAYOUT: [LayoutField; 12] = [
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
    field("cf", 175, 32),
];

/// The bindings, for code that treats them alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    CoinReveal,
    DataReveal,
    Hold,
    /// The coin reveal of the ordinary class, S1 version 2.
    CoinRevealV2,
    /// The policy reveal of the policy class, S4.
    PolicyReveal,
    /// `KNOW_ACTION_v1`, a policy action.
    Action,
    /// `KNOW_PREIMAGE_v1`, the statement checker's statement.
    Preimage,
}

impl Binding {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::CoinReveal => TAG_COIN_REVEAL_BINDING,
            Self::DataReveal => TAG_DATA_REVEAL_BINDING,
            Self::Hold => TAG_HOLD_BINDING,
            Self::CoinRevealV2 => TAG_COIN_REVEAL_BINDING_V2,
            Self::PolicyReveal => TAG_POLICY_REVEAL_BINDING_V1,
            Self::Action => TAG_ACTION_BINDING_V1,
            Self::Preimage => TAG_PREIMAGE_BINDING_V1,
        }
    }

    pub const fn layout(self) -> &'static [LayoutField] {
        match self {
            Self::CoinReveal => &COIN_REVEAL_LAYOUT,
            Self::DataReveal => &DATA_REVEAL_LAYOUT,
            Self::Hold => &HOLD_LAYOUT,
            Self::CoinRevealV2 => &COIN_REVEAL_V2_LAYOUT,
            Self::PolicyReveal => &POLICY_REVEAL_LAYOUT,
            Self::Action => &ACTION_LAYOUT,
            Self::Preimage => &PREIMAGE_LAYOUT,
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
    /// A writer for statement version 1 (spec 02).
    pub(crate) fn new(binding: Binding, params: &ChainParams, statement: u8, type_tag: [u8; 2], purpose: u8) -> Self {
        Self::with_version(binding, params, statement, STATEMENT_VERSION_1, type_tag, purpose)
    }

    /// A writer for any statement version.
    pub(crate) fn with_version(
        binding: Binding,
        params: &ChainParams,
        statement: u8,
        statement_version: u8,
        type_tag: [u8; 2],
        purpose: u8,
    ) -> Self {
        let mut writer = Self::untyped(binding, params, statement, statement_version, purpose);
        writer.put("type", &type_tag);
        writer
    }

    /// A writer for a native statement of spec 10, section 9, whose layout
    /// has no `type` field: it writes the chain constants, the statement,
    /// its version and the purpose.
    pub(crate) fn untyped(
        binding: Binding,
        params: &ChainParams,
        statement: u8,
        statement_version: u8,
        purpose: u8,
    ) -> Self {
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
            .put("statement_version", &[statement_version])
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
        for binding in [
            Binding::CoinReveal,
            Binding::DataReveal,
            Binding::Hold,
            Binding::CoinRevealV2,
            Binding::PolicyReveal,
            Binding::Action,
            Binding::Preimage,
        ] {
            let mut next = 0;
            for f in binding.layout() {
                assert_eq!(f.offset, next, "{}", f.name);
                next += f.width;
            }
        }
    }

    /// Spec 10, section 4.2: 607 bytes, 636 with the tag, five permutations,
    /// and no `rule` field.
    #[test]
    fn the_version_2_coin_reveal_binding_has_no_rule() {
        let b = Binding::CoinRevealV2;
        assert_eq!((b.fields_len(), b.input_len(), b.permutations()), (607, 636, 5));
        assert!(b.layout().iter().all(|f| f.name != "rule"));
        let v1: alloc::vec::Vec<_> = COIN_REVEAL_LAYOUT.iter().map(|f| f.name).filter(|&n| n != "rule").collect();
        let v2: alloc::vec::Vec<_> = b.layout().iter().map(|f| f.name).collect();
        assert_eq!(v1, v2);
    }

    /// Spec 10, section 5.1: 767 bytes, 798 with the 31-byte tag, six
    /// permutations; no `recipient`, no `rule` and no `override_hash`.
    #[test]
    fn the_policy_reveal_binding_has_the_spec_shape() {
        let b = Binding::PolicyReveal;
        assert_eq!(tag_bytes(b.tag()).len(), 31);
        assert_eq!((b.fields_len(), b.input_len(), b.permutations()), (767, 798, 6));
        for name in ["recipient", "rule", "override_hash"] {
            assert!(b.layout().iter().all(|f| f.name != name), "{name}");
        }
        assert_eq!(b.offset("policy_address"), 207);
        assert_eq!(b.offset("remainder_note"), 387);
    }

    /// Spec 10, sections 8.2 and 9.2: the native bindings have no `type`,
    /// and the untyped writer fills every field but the statement's own.
    #[test]
    fn the_native_bindings_have_no_type() {
        assert_eq!((Binding::Action.fields_len(), Binding::Action.input_len()), (273, 297));
        assert_eq!((Binding::Preimage.fields_len(), Binding::Preimage.input_len()), (161, 187));
        for b in [Binding::Action, Binding::Preimage] {
            assert!(b.layout().iter().all(|f| f.name != "type"));
            assert_eq!(b.offset("purpose"), 44);
        }
        let params = ChainParams {
            chain_id: [1; 8],
            version: PROTOCOL_VERSION_1,
            domain: [2; 32],
        };
        let mut w = FieldWriter::untyped(Binding::Preimage, &params, STATEMENT_KNOW_PREIMAGE, 1, PURPOSE_PREIMAGE);
        let fields = w.put("policy_address", &[3; 20]).put("y", &[4; 32]).put("context", &[5; 64]).finish();
        assert_eq!(fields[42..45], [0x06, 0x01, 0x07]);
    }
}
