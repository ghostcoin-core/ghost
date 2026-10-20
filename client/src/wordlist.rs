//! The 2,048-word English list of BIP-39.
//!
//! `wordlist/english.txt` is the file `bip-0039/english.txt` of the
//! bitcoin/bips repository (<https://github.com/bitcoin/bips>), unchanged: one
//! word per line, each line ending in a newline. That repository publishes it
//! under the MIT licence. This module only reads the file, so a change to the
//! list is a change to that data file alone.

/// The number of words in the list.
pub const WORD_COUNT: usize = 2048;

/// The file's bytes, exactly as published.
const SOURCE: &str = include_str!("wordlist/english.txt");

/// The words in the file's order (which is sorted), checked when the crate
/// compiles: the build fails unless the file holds exactly 2,048 non-empty
/// lines, each ending in a newline.
pub const WORDLIST: [&str; WORD_COUNT] = split_lines(SOURCE);

const fn split_lines(text: &'static str) -> [&'static str; WORD_COUNT] {
    let mut words = [""; WORD_COUNT];
    let mut rest = text.as_bytes();
    let mut count = 0;
    while !rest.is_empty() {
        let mut end = 0;
        while end < rest.len() && rest[end] != b'\n' {
            end += 1;
        }
        assert!(end < rest.len(), "the word list must end with a newline");
        assert!(end > 0, "the word list has an empty line");
        assert!(count < WORD_COUNT, "the word list has more than 2048 words");
        let (word, tail) = rest.split_at(end);
        words[count] = match core::str::from_utf8(word) {
            Ok(word) => word,
            Err(_) => panic!("the word list is not UTF-8"),
        };
        rest = tail.split_at(1).1;
        count += 1;
    }
    assert!(count == WORD_COUNT, "the word list has fewer than 2048 words");
    words
}
