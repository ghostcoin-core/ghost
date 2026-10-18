//! IEEE 754 binary64 addition, subtraction, multiplication, division and
//! square root under each of the four rounding modes RandomX's `CFROUND`
//! selects, computed exactly with integers. WebAssembly and Rust both fix
//! the rounding mode to nearest-even, so the program VM cannot use the
//! hardware for the other three.
//!
//! RandomX keeps its registers away from NaN, infinity and subnormal values;
//! they are handled here only so that every input has a defined result
//! (x86's default NaN for an invalid operation, gradual underflow).

/// RandomX rounding modes, in `CFROUND`'s numbering.
pub const NEAREST: u8 = 0;
pub const DOWN: u8 = 1;
pub const UP: u8 = 2;
pub const TOWARD_ZERO: u8 = 3;

const SIGN: u64 = 1 << 63;
const DEFAULT_NAN: u64 = 0xfff8_0000_0000_0000;
const QUIET: u64 = 1 << 51;
const INFINITY: u64 = 0x7ff0_0000_0000_0000;
const MAX_FINITE: u64 = 0x7fef_ffff_ffff_ffff;

enum Class {
    Nan,
    Infinite,
    Zero,
    /// `m * 2^e`, `m` nonzero.
    Finite(u64, i32),
}

fn classify(bits: u64) -> Class {
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1 << 52) - 1);
    match (exponent, fraction) {
        (0x7ff, 0) => Class::Infinite,
        (0x7ff, _) => Class::Nan,
        (0, 0) => Class::Zero,
        (0, f) => Class::Finite(f, -1074),
        (e, f) => Class::Finite(f | (1 << 52), e - 1075),
    }
}

fn nan_of(a: u64, b: u64) -> u64 {
    if matches!(classify(a), Class::Nan) { a | QUIET } else { b | QUIET }
}

/// Rounds `m * 2^e`, plus a nonzero amount below one unit of `m` when
/// `sticky` is set, to a double with sign `negative`. When `sticky` is set
/// the caller gives `m` at least 60 significant bits.
fn round(negative: bool, m: u128, e: i32, sticky: bool, mode: u8) -> u64 {
    let sign = if negative { SIGN } else { 0 };
    if m == 0 {
        return sign;
    }
    let top = e + (127 - m.leading_zeros() as i32);
    let mut lsb = (top - 52).max(-1074);
    let drop = lsb - e;
    let mut q;
    if drop <= 0 {
        debug_assert!(!sticky);
        q = (m << (-drop) as u32) as u64;
    } else {
        let drop = drop as u32;
        let (kept, rem) = if drop >= 128 { (0, m) } else { (m >> drop, m & ((1u128 << drop) - 1)) };
        // Compares the dropped part with half a unit of the result.
        let half = if drop > 128 { core::cmp::Ordering::Less } else { rem.cmp(&(1u128 << (drop - 1))) };
        let inexact = rem != 0 || sticky;
        q = kept as u64;
        let up = match mode {
            NEAREST => match half {
                core::cmp::Ordering::Greater => true,
                core::cmp::Ordering::Equal => sticky || q & 1 == 1,
                core::cmp::Ordering::Less => false,
            },
            DOWN => negative && inexact,
            UP => !negative && inexact,
            TOWARD_ZERO => false,
            _ => unreachable!("a rounding mode is 0 to 3"),
        };
        if up {
            q += 1;
            if q == 1 << 53 {
                q >>= 1;
                lsb += 1;
            }
        }
    }
    if q < 1 << 52 {
        return sign | q;
    }
    let exponent = lsb + 52 + 1023;
    if exponent >= 0x7ff {
        let to_infinity = match mode {
            NEAREST => true,
            DOWN => negative,
            UP => !negative,
            TOWARD_ZERO => false,
            _ => unreachable!("a rounding mode is 0 to 3"),
        };
        return sign | if to_infinity { INFINITY } else { MAX_FINITE };
    }
    sign | ((exponent as u64) << 52) | (q - (1 << 52))
}

pub fn add(a: u64, b: u64, mode: u8) -> u64 {
    let (sa, sb) = (a & SIGN != 0, b & SIGN != 0);
    match (classify(a), classify(b)) {
        (Class::Nan, _) | (_, Class::Nan) => nan_of(a, b),
        (Class::Infinite, Class::Infinite) => if sa == sb { a } else { DEFAULT_NAN },
        (Class::Infinite, _) => a,
        (_, Class::Infinite) => b,
        (Class::Zero, Class::Zero) => {
            let negative = if mode == DOWN { sa || sb } else { sa && sb };
            if negative { SIGN } else { 0 }
        }
        (Class::Zero, _) => b,
        (_, Class::Zero) => a,
        (Class::Finite(ma, ea), Class::Finite(mb, eb)) => {
            // Order so that `x` has the larger exponent.
            let ((mx, ex, sx), (my, ey, sy)) =
                if ea >= eb { ((ma, ea, sa), (mb, eb, sb)) } else { ((mb, eb, sb), (ma, ea, sa)) };
            let diff = (ex - ey) as u32;
            if diff > 74 {
                // `y` is below one unit of `x * 2^22`, so it only decides the
                // direction of rounding (`x` is normal here, so the scaled
                // value has at least 74 bits).
                let big = u128::from(mx) << 22;
                let m = if sx == sy { big } else { big - 1 };
                return round(sx, m, ex - 22, true, mode);
            }
            let x = u128::from(mx) << diff;
            let y = u128::from(my);
            if sx == sy {
                round(sx, x + y, ey, false, mode)
            } else if x == y {
                if mode == DOWN { SIGN } else { 0 }
            } else if x > y {
                round(sx, x - y, ey, false, mode)
            } else {
                round(sy, y - x, ey, false, mode)
            }
        }
    }
}

pub fn sub(a: u64, b: u64, mode: u8) -> u64 {
    if matches!(classify(b), Class::Nan) {
        return nan_of(a, b);
    }
    add(a, b ^ SIGN, mode)
}

pub fn mul(a: u64, b: u64, mode: u8) -> u64 {
    let negative = (a ^ b) & SIGN != 0;
    let sign = if negative { SIGN } else { 0 };
    match (classify(a), classify(b)) {
        (Class::Nan, _) | (_, Class::Nan) => nan_of(a, b),
        (Class::Infinite, Class::Zero) | (Class::Zero, Class::Infinite) => DEFAULT_NAN,
        (Class::Infinite, _) | (_, Class::Infinite) => sign | INFINITY,
        (Class::Zero, _) | (_, Class::Zero) => sign,
        (Class::Finite(ma, ea), Class::Finite(mb, eb)) => {
            round(negative, u128::from(ma) * u128::from(mb), ea + eb, false, mode)
        }
    }
}

/// `m * 2^e` with the leading bit of `m` at bit 52.
fn normalize(m: u64, e: i32) -> (u64, i32) {
    let shift = m.leading_zeros() as i32 - 11;
    (m << shift, e - shift)
}

pub fn div(a: u64, b: u64, mode: u8) -> u64 {
    let negative = (a ^ b) & SIGN != 0;
    let sign = if negative { SIGN } else { 0 };
    match (classify(a), classify(b)) {
        (Class::Nan, _) | (_, Class::Nan) => nan_of(a, b),
        (Class::Infinite, Class::Infinite) | (Class::Zero, Class::Zero) => DEFAULT_NAN,
        (Class::Infinite, _) | (_, Class::Zero) => sign | INFINITY,
        (Class::Zero, _) | (_, Class::Infinite) => sign,
        (Class::Finite(ma, ea), Class::Finite(mb, eb)) => {
            let (ma, ea) = normalize(ma, ea);
            let (mb, eb) = normalize(mb, eb);
            let n = u128::from(ma) << 75;
            let d = u128::from(mb);
            round(negative, n / d, ea - eb - 75, n % d != 0, mode)
        }
    }
}

pub fn sqrt(a: u64, mode: u8) -> u64 {
    match classify(a) {
        Class::Nan => a | QUIET,
        Class::Zero => a,
        _ if a & SIGN != 0 => DEFAULT_NAN,
        Class::Infinite => a,
        Class::Finite(m, e) => {
            let (m, mut e) = normalize(m, e);
            let mut wide = u128::from(m);
            if e & 1 != 0 {
                wide <<= 1;
                e -= 1;
            }
            let n = wide << 72;
            let root = isqrt(n);
            round(false, root, (e - 72) / 2, root * root != n, mode)
        }
    }
}

/// The integer square root, rounded down.
fn isqrt(n: u128) -> u128 {
    let mut root = 0u128;
    let mut bit = 1u128 << 126;
    let mut rest = n;
    while bit > rest {
        bit >>= 2;
    }
    while bit != 0 {
        if rest >= root + bit {
            rest -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}
