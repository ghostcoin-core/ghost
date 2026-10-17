//! The amount word of spec 02, section 10, and conservation on its limbs.
//!
//! An amount is a 32-byte big-endian unsigned integer. It is valid if and only
//! if its first 20 bytes are zero, so it lies in `[0, 2^96 - 1]`. The proof
//! reads its last 12 bytes as six 16-bit limbs and does all arithmetic on
//! those limbs; there is no other encoding.
//!
//! Conservation `v = out + v' + fee` is checked with carries `c0 = 0` and, for
//! limb `j = 0 .. 5` (least significant first),
//!
//! ```text
//! out_j + v'_j + fee_j + c_j = v_j + 2^16 * c_(j+1),   c_(j+1) in {0, 1, 2}
//! ```
//!
//! and `c6 = 0`. Every side stays below `2^18`, far below the BabyBear modulus,
//! so the equations hold over the integers.

/// Number of 16-bit limbs of an amount.
pub const AMOUNT_LIMBS: usize = 6;

/// Bytes of an amount word that must be zero.
pub const AMOUNT_HIGH_BYTES: usize = 20;

/// `V_MAX = 2^96 - 1`.
pub const V_MAX: u128 = (1 << 96) - 1;

/// Number of carries the limb equations need (`c1` to `c5`).
pub const CARRIES: usize = AMOUNT_LIMBS - 1;

/// The word of an integer, valid or not.
pub const fn amount_word(value: u128) -> [u8; 32] {
    let low = value.to_be_bytes();
    let mut word = [0u8; 32];
    let mut i = 0;
    while i < 16 {
        word[16 + i] = low[i];
        i += 1;
    }
    word
}

/// Whether the word is a valid amount: its first 20 bytes are zero.
pub fn amount_is_valid(word: &[u8; 32]) -> bool {
    word[..AMOUNT_HIGH_BYTES].iter().all(|&byte| byte == 0)
}

/// The value of a valid word, or `None` if any of its high 20 bytes is set.
pub fn amount_value(word: &[u8; 32]) -> Option<u128> {
    amount_is_valid(word).then(|| {
        word[16..]
            .iter()
            .fold(0u128, |acc, &byte| acc << 8 | u128::from(byte))
    })
}

/// The six limbs of the last 12 bytes, most significant first (`a5 .. a0`),
/// whatever the high bytes hold.
pub fn amount_limbs(word: &[u8; 32]) -> [u16; AMOUNT_LIMBS] {
    core::array::from_fn(|k| {
        u16::from(word[AMOUNT_HIGH_BYTES + 2 * k]) << 8 | u16::from(word[AMOUNT_HIGH_BYTES + 2 * k + 1])
    })
}

/// Limb `j` counted from the least significant (`a_j`).
pub(crate) fn limb(word: &[u8; 32], j: usize) -> u32 {
    u32::from(amount_limbs(word)[AMOUNT_LIMBS - 1 - j])
}

/// Position in the word of the high and low byte of limb `j` (least
/// significant first).
pub(crate) const fn limb_bytes(j: usize) -> (usize, usize) {
    (30 - 2 * j, 31 - 2 * j)
}

/// The carries `c1 .. c5` of the limb equations, if all four words are valid
/// and the equations hold with every carry in `{0, 1, 2}` and `c6 = 0`.
pub fn conservation_carries(
    v: &[u8; 32],
    out: &[u8; 32],
    remainder: &[u8; 32],
    fee: &[u8; 32],
) -> Option<[u8; CARRIES]> {
    if ![v, out, remainder, fee].into_iter().all(amount_is_valid) {
        return None;
    }
    let mut carries = [0u8; CARRIES];
    let mut carry = 0u32;
    for j in 0..AMOUNT_LIMBS {
        let left = limb(out, j) + limb(remainder, j) + limb(fee, j) + carry;
        let diff = left.checked_sub(limb(v, j))?;
        if diff % (1 << 16) != 0 {
            return None;
        }
        carry = diff >> 16;
        if carry > 2 {
            return None;
        }
        if j + 1 < AMOUNT_LIMBS {
            carries[j] = carry as u8;
        }
    }
    (carry == 0).then_some(carries)
}

/// Whether `v = out + v' + fee` holds under the limb rule. For valid words
/// this is the same as the integer equation.
pub fn conservation_holds(v: &[u8; 32], out: &[u8; 32], remainder: &[u8; 32], fee: &[u8; 32]) -> bool {
    conservation_carries(v, out, remainder, fee).is_some()
}

/// Carries a prover that ignores the rule would put in its trace: the honest
/// carries where they exist, otherwise a best guess clamped to `{0, 1, 2}`.
/// The constraints reject such a trace; this only lets a test try.
pub(crate) fn guessed_carries(
    v: &[u8; 32],
    out: &[u8; 32],
    remainder: &[u8; 32],
    fee: &[u8; 32],
) -> [u8; CARRIES] {
    if let Some(carries) = conservation_carries(v, out, remainder, fee) {
        return carries;
    }
    let mut carries = [0u8; CARRIES];
    let mut carry = 0u32;
    for (j, slot) in carries.iter_mut().enumerate() {
        let left = limb(out, j) + limb(remainder, j) + limb(fee, j) + carry;
        carry = (left.saturating_sub(limb(v, j)) >> 16).min(2);
        *slot = carry as u8;
    }
    carries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip() {
        for value in [0, 1, 65_535, 65_536, 1_000_000_000_000_000_000, V_MAX] {
            assert_eq!(amount_value(&amount_word(value)), Some(value));
        }
        assert_eq!(amount_value(&amount_word(V_MAX + 1)), None);
    }

    #[test]
    fn limb_rule_agrees_with_integers_near_the_edges() {
        let cases: [(u128, u128, u128, u128); 6] = [
            (V_MAX, V_MAX, 0, 0),
            (V_MAX, 0, V_MAX, 0),
            (V_MAX, 1, 1, V_MAX - 2),
            (0, 0, 0, 0),
            (65_536, 65_535, 0, 1),
            (V_MAX, V_MAX - 1, 0, 0),
        ];
        for (v, out, rem, fee) in cases {
            let integer = out + rem + fee == v;
            let limbs = conservation_holds(&amount_word(v), &amount_word(out), &amount_word(rem), &amount_word(fee));
            assert_eq!(integer, limbs, "{v} {out} {rem} {fee}");
        }
    }
}
