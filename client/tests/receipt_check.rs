//! Block receipts checked against a header's receipts root, and the coin
//! tree's leaves, notes and spent markers checked against the receipts.
//!
//! The expected roots come from a separate, simple trie written here (insert
//! one key at a time, then encode), not from the library's.

use ghost_client::hash::{k, keccak256};
use ghost_client::receipts::{
    check_block_receipts, check_block_receipts_against_header, check_leaves, check_markers,
    header_receipts_root, receipts_root, CheckedBlock, CoinRecord, ReceiptError, COIN_TREE_ACCOUNT,
};
use ghost_client::{Commitment, Marker, TreeLeaf, NOTE_BYTES};

// ---------------------------------------------------------------- RLP

fn rlp_length(out: &mut Vec<u8>, len: usize, short: u8) {
    if len < 56 {
        out.push(short + len as u8);
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        out.push(short + 55 + (be.len() - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if b.len() == 1 && b[0] < 0x80 {
        out.push(b[0]);
    } else {
        rlp_length(&mut out, b.len(), 0x80);
        out.extend_from_slice(b);
    }
    out
}

fn rlp_uint(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    let skip = be.iter().take_while(|&&b| b == 0).count();
    rlp_bytes(&be[skip..])
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = Vec::new();
    rlp_length(&mut out, payload.len(), 0xc0);
    out.extend_from_slice(&payload);
    out
}

// ---------------------------------------------------------------- simple trie

enum Node {
    Empty,
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, Box<Node>),
    Branch(Vec<Node>, Option<Vec<u8>>),
}

fn empty_branch() -> Vec<Node> {
    (0..16).map(|_| Node::Empty).collect()
}

fn common(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Puts a leaf for the rest of a key into a branch being built.
fn branch_put(children: &mut [Node], value: &mut Option<Vec<u8>>, rest: &[u8], v: Vec<u8>) {
    if rest.is_empty() {
        *value = Some(v);
    } else {
        children[usize::from(rest[0])] = Node::Leaf(rest[1..].to_vec(), v);
    }
}

fn wrap(prefix: &[u8], node: Node) -> Node {
    if prefix.is_empty() { node } else { Node::Extension(prefix.to_vec(), Box::new(node)) }
}

fn insert(node: Node, key: &[u8], v: Vec<u8>) -> Node {
    match node {
        Node::Empty => Node::Leaf(key.to_vec(), v),
        Node::Leaf(path, old) => {
            if path == key {
                return Node::Leaf(path, v);
            }
            let n = common(&path, key);
            let mut children = empty_branch();
            let mut value = None;
            branch_put(&mut children, &mut value, &path[n..], old);
            branch_put(&mut children, &mut value, &key[n..], v);
            wrap(&key[..n], Node::Branch(children, value))
        }
        Node::Extension(path, child) => {
            let n = common(&path, key);
            if n == path.len() {
                return Node::Extension(path, Box::new(insert(*child, &key[n..], v)));
            }
            let mut children = empty_branch();
            let mut value = None;
            children[usize::from(path[n])] = wrap(&path[n + 1..], *child);
            branch_put(&mut children, &mut value, &key[n..], v);
            wrap(&path[..n], Node::Branch(children, value))
        }
        Node::Branch(mut children, value) => {
            if key.is_empty() {
                return Node::Branch(children, Some(v));
            }
            let slot = usize::from(key[0]);
            let child = std::mem::replace(&mut children[slot], Node::Empty);
            children[slot] = insert(child, &key[1..], v);
            Node::Branch(children, value)
        }
    }
}

fn compact(path: &[u8], leaf: bool) -> Vec<u8> {
    let mut nibbles = vec![if leaf { 2 } else { 0 }];
    if path.len() % 2 == 1 {
        nibbles[0] += 1;
    } else {
        nibbles.push(0);
    }
    nibbles.extend_from_slice(path);
    nibbles.chunks(2).map(|p| p[0] * 16 + p[1]).collect()
}

fn encode(node: &Node) -> Vec<u8> {
    match node {
        Node::Empty => rlp_bytes(&[]),
        Node::Leaf(path, v) => rlp_list(&[rlp_bytes(&compact(path, true)), rlp_bytes(v)]),
        Node::Extension(path, child) => rlp_list(&[rlp_bytes(&compact(path, false)), child_ref(child)]),
        Node::Branch(children, value) => {
            let mut items: Vec<Vec<u8>> = children.iter().map(child_ref).collect();
            items.push(rlp_bytes(value.as_deref().unwrap_or(&[])));
            rlp_list(&items)
        }
    }
}

fn child_ref(node: &Node) -> Vec<u8> {
    let encoded = encode(node);
    if encoded.len() < 32 { encoded } else { rlp_bytes(&keccak256(&encoded)) }
}

fn simple_root(pairs: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    let mut root = Node::Empty;
    for (key, value) in pairs {
        let nibbles: Vec<u8> = key.iter().flat_map(|b| [b >> 4, b & 15]).collect();
        root = insert(root, &nibbles, value.clone());
    }
    keccak256(&encode(&root))
}

fn simple_receipts_root(receipts: &[Vec<u8>]) -> [u8; 32] {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> =
        receipts.iter().enumerate().map(|(i, r)| (rlp_uint(i as u64), r.clone())).collect();
    simple_root(&pairs)
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

// ---------------------------------------------------------------- blocks

const OTHER_ADDRESS: [u8; 20] = [0x11; 20];

fn log(address: &[u8], topics: &[[u8; 32]], data: &[u8]) -> Vec<u8> {
    let topics: Vec<Vec<u8>> = topics.iter().map(|t| rlp_bytes(t)).collect();
    rlp_list(&[rlp_bytes(address), rlp_list(&topics), rlp_bytes(data)])
}

fn receipt(kind: Option<u8>, status: u64, gas: u64, logs: &[Vec<u8>]) -> Vec<u8> {
    let body = rlp_list(&[rlp_uint(status), rlp_uint(gas), rlp_bytes(&[0u8; 256]), rlp_list(logs)]);
    match kind {
        Some(kind) => [vec![kind], body].concat(),
        None => body,
    }
}

fn leaf_at(tree: u32, position: u32) -> Commitment {
    Commitment::from_bytes(keccak256(&[tree.to_be_bytes(), position.to_be_bytes()].concat()))
}

fn note_at(position: u32) -> [u8; NOTE_BYTES] {
    core::array::from_fn(|j| (position as usize * 7 + j) as u8)
}

fn marker_at(position: u32) -> Marker {
    Marker::from_bytes(keccak256(&[b"marker".as_slice(), &position.to_be_bytes()].concat()))
}

fn commit_log(tree: u32, position: u32) -> Vec<u8> {
    let data = [
        &tree.to_be_bytes()[..],
        &position.to_be_bytes(),
        leaf_at(tree, position).as_bytes(),
        &[0x05; 32],
        &note_at(position),
    ]
    .concat();
    log(&COIN_TREE_ACCOUNT, &[k("ghost/commit-receipt/v1", &[])], &data)
}

fn reveal_log(tree: u32, position: u32) -> Vec<u8> {
    let data = [
        &tree.to_be_bytes()[..],
        &position.to_be_bytes(),
        leaf_at(tree, position).as_bytes(),
        &note_at(position),
        &[0x22; 20],
        &[0x01; 32],
    ]
    .concat();
    log(&COIN_TREE_ACCOUNT, &[k("ghost/reveal-receipt/v1", &[]), *marker_at(position).as_bytes()], &data)
}

/// An honest block of `count` receipts appending to coin tree 0 from
/// `start`: legacy receipts with other logs, commits, reveals, a failed
/// receipt and receipts carrying several logs. Returns the receipts, the
/// leaves they append and the markers they spend.
struct Block {
    receipts: Vec<Vec<u8>>,
    leaves: Vec<TreeLeaf>,
    markers: Vec<Marker>,
}

fn block(start: u32, count: usize) -> Block {
    let mut receipts = Vec::new();
    let mut leaves = Vec::new();
    let mut markers = Vec::new();
    let mut position = start;
    let mut gas = 0;
    let mut append = |leaves: &mut Vec<TreeLeaf>| {
        let p = position;
        leaves.push(TreeLeaf { commitment: leaf_at(0, p), note: note_at(p) });
        position += 1;
        p
    };
    for i in 0..count {
        gas += 21_000;
        let r = match i % 5 {
            0 => receipt(None, 1, gas, &[log(&OTHER_ADDRESS, &[[0x33; 32]], b"other")]),
            1 => {
                let p = append(&mut leaves);
                receipt(Some(0x50), 1, gas, &[commit_log(0, p)])
            }
            2 => {
                let p = append(&mut leaves);
                markers.push(marker_at(p));
                receipt(Some(0x50), 1, gas, &[reveal_log(0, p)])
            }
            3 => receipt(Some(0x52), 0, gas, &[]),
            _ => {
                let c = append(&mut leaves);
                let r = append(&mut leaves);
                markers.push(marker_at(r));
                let other = log(&OTHER_ADDRESS, &[], &[0xee; 300]);
                receipt(Some(0x50), 1, gas, &[other, commit_log(0, c), reveal_log(0, r)])
            }
        };
        receipts.push(r);
    }
    Block { receipts, leaves, markers }
}

fn checked(block: &Block) -> CheckedBlock {
    check_block_receipts(&block.receipts, &simple_receipts_root(&block.receipts)).expect("an honest block checks")
}

fn header(receipts_root: &[u8; 32]) -> Vec<u8> {
    rlp_list(&[
        rlp_bytes(&[0x01; 32]),
        rlp_bytes(&[0x02; 32]),
        rlp_bytes(&[0x03; 20]),
        rlp_bytes(&[0x04; 32]),
        rlp_bytes(&[0x05; 32]),
        rlp_bytes(receipts_root),
        rlp_bytes(&[0u8; 256]),
        rlp_uint(16_777_216),
        rlp_uint(1),
        rlp_uint(30_000_000),
        rlp_uint(126_000),
        rlp_uint(1_798_767_630),
        rlp_bytes(&[]),
        rlp_bytes(&[0u8; 32]),
        rlp_bytes(&[0u8; 8]),
        rlp_uint(1_000_000_000),
        rlp_bytes(&[0x06; 32]),
        rlp_bytes(&[0x07; 32]),
    ])
}

// ---------------------------------------------------------------- the roots

#[test]
fn the_simple_trie_gives_known_roots() {
    let empty: [u8; 32] = unhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").try_into().unwrap();
    assert_eq!(simple_root(&[]), empty);
    let dogs = [("doe", "reindeer"), ("dog", "puppy"), ("dogglesworth", "cat")]
        .map(|(key, value)| (key.as_bytes().to_vec(), value.as_bytes().to_vec()));
    assert_eq!(simple_root(&dogs).to_vec(), unhex("8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3"));
}

#[test]
fn the_empty_block_has_the_empty_root() {
    let none: [Vec<u8>; 0] = [];
    let empty: [u8; 32] = unhex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").try_into().unwrap();
    assert_eq!(receipts_root(&none), empty);
    let block = check_block_receipts(&none, &empty).unwrap();
    assert!(block.records().is_empty());
    assert_eq!(check_leaves(&[block.clone()], 0, 0, &[]), Ok(()));
    assert_eq!(check_markers(&[block], &[]), Ok(()));
}

#[test]
fn receipts_roots_match_the_simple_trie_at_every_size() {
    // Up to and past 128 receipts: one-byte keys, the 0x80 key of index 0,
    // two-byte keys from 128 on, branch and extension nodes.
    for count in [1, 2, 3, 16, 17, 127, 128, 129, 200, 300] {
        let block = block(0, count);
        assert_eq!(receipts_root(&block.receipts), simple_receipts_root(&block.receipts), "{count} receipts");
    }
}

// ---------------------------------------------------------------- honest

#[test]
fn an_honest_block_checks() {
    let honest = block(0, 150);
    assert!(honest.receipts.len() > 127);
    let root = simple_receipts_root(&honest.receipts);
    let checked = check_block_receipts(&honest.receipts, &root).unwrap();
    assert_eq!(checked.records().len(), honest.leaves.len());

    // Records are in block and log order, with the layout's fields.
    for (index, record) in checked.records().iter().enumerate() {
        let appended = record.appended();
        assert_eq!(appended.tree_index, 0);
        assert_eq!(appended.position, index as u32);
        assert_eq!(appended.leaf, leaf_at(0, index as u32));
        assert_eq!(appended.note, note_at(index as u32));
        match record {
            CoinRecord::Commit { v, .. } => assert_eq!(*v, [0x05; 32]),
            CoinRecord::Reveal { marker, recipient, out, .. } => {
                assert_eq!(*marker, marker_at(index as u32));
                assert_eq!(*recipient, [0x22; 20]);
                assert_eq!(*out, [0x01; 32]);
            }
        }
    }

    let blocks = [checked];
    assert_eq!(check_leaves(&blocks, 0, 0, &honest.leaves), Ok(()));
    assert_eq!(check_leaves(&blocks, 0, 40, &honest.leaves[40..]), Ok(()));
    assert_eq!(check_markers(&blocks, &honest.markers), Ok(()));

    let header = header(&root);
    assert_eq!(header_receipts_root(&header), Ok(root));
    assert_eq!(check_block_receipts_against_header(&header, &honest.receipts).as_ref(), Ok(&blocks[0]));
}

#[test]
fn honest_blocks_check_in_sequence() {
    let first = block(0, 40);
    let second = block(first.leaves.len() as u32, 40);
    let blocks = [checked(&first), checked(&second)];
    let leaves = [first.leaves.clone(), second.leaves.clone()].concat();
    let markers = [first.markers.clone(), second.markers.clone()].concat();
    assert_eq!(check_leaves(&blocks, 0, 0, &leaves), Ok(()));
    assert_eq!(check_leaves(&blocks, 0, 50, &leaves[50..]), Ok(()));
    assert_eq!(check_markers(&blocks, &markers), Ok(()));
    // Records of another tree index are not this run's.
    assert_eq!(check_leaves(&blocks, 1, 0, &[]), Ok(()));
}

// ---------------------------------------------------------------- refused

#[test]
fn a_wrong_root_is_refused() {
    let honest = block(0, 150);
    let mut root = simple_receipts_root(&honest.receipts);
    root[31] ^= 1;
    assert_eq!(check_block_receipts(&honest.receipts, &root), Err(ReceiptError::RootMismatch));
    assert_eq!(check_block_receipts_against_header(&header(&root), &honest.receipts), Err(ReceiptError::RootMismatch));
    let none: [Vec<u8>; 0] = [];
    assert_eq!(check_block_receipts(&none, &root), Err(ReceiptError::RootMismatch));
    // A header that does not decode gives no root.
    let mut bad_header = header(&root);
    bad_header.push(0);
    assert!(matches!(check_block_receipts_against_header(&bad_header, &honest.receipts), Err(ReceiptError::Header(_))));
}

#[test]
fn a_changed_note_is_refused() {
    let honest = block(0, 150);
    let root = simple_receipts_root(&honest.receipts);

    // In the downloaded run.
    let blocks = [checked(&honest)];
    let mut leaves = honest.leaves.clone();
    leaves[17].note[100] ^= 1;
    assert_eq!(check_leaves(&blocks, 0, 0, &leaves), Err(ReceiptError::NoteMismatch { position: 17 }));
    assert_eq!(check_leaves(&blocks, 0, 10, &leaves[10..]), Err(ReceiptError::NoteMismatch { position: 17 }));

    // In a receipt: the root no longer matches.
    let mut receipts = honest.receipts.clone();
    let note = note_at(1);
    let at = receipts[2].windows(NOTE_BYTES).position(|w| w == note).unwrap();
    receipts[2][at + 3] ^= 1;
    assert_eq!(check_block_receipts(&receipts, &root), Err(ReceiptError::RootMismatch));
}

#[test]
fn a_changed_leaf_is_refused() {
    let honest = block(0, 150);
    let blocks = [checked(&honest)];
    let mut leaves = honest.leaves.clone();
    leaves[30].commitment = leaf_at(0, 999);
    assert_eq!(check_leaves(&blocks, 0, 0, &leaves), Err(ReceiptError::LeafMismatch { position: 30 }));
}

#[test]
fn a_dropped_receipt_is_refused() {
    let honest = block(0, 150);
    let root = simple_receipts_root(&honest.receipts);
    let mut receipts = honest.receipts.clone();
    receipts.remove(6);
    assert_eq!(check_block_receipts(&receipts, &root), Err(ReceiptError::RootMismatch));
    receipts = honest.receipts.clone();
    receipts.pop();
    assert_eq!(check_block_receipts(&receipts, &root), Err(ReceiptError::RootMismatch));

    // A dropped block between two checked ones leaves a gap in the records.
    let first = block(0, 20);
    let second = block(first.leaves.len() as u32, 20);
    let third = block((first.leaves.len() + second.leaves.len()) as u32, 20);
    let leaves = [first.leaves.clone(), second.leaves.clone(), third.leaves.clone()].concat();
    let gap = [checked(&first), checked(&third)];
    assert!(matches!(check_leaves(&gap, 0, 0, &leaves), Err(ReceiptError::RecordSequence { .. })));
    let markers = [first.markers.clone(), second.markers.clone(), third.markers.clone()].concat();
    assert!(check_markers(&gap, &markers).is_err());
}

#[test]
fn a_dropped_leaf_is_refused() {
    let honest = block(0, 150);
    let blocks = [checked(&honest)];
    let mut leaves = honest.leaves.clone();
    leaves.remove(12);
    assert!(check_leaves(&blocks, 0, 0, &leaves).is_err());
    leaves = honest.leaves.clone();
    let last = leaves.len() as u32 - 1;
    leaves.pop();
    assert_eq!(check_leaves(&blocks, 0, 0, &leaves), Err(ReceiptError::LeafMissing { position: last }));
}

#[test]
fn a_reordered_receipt_is_refused() {
    let honest = block(0, 150);
    let root = simple_receipts_root(&honest.receipts);
    let mut receipts = honest.receipts.clone();
    receipts.swap(1, 2);
    assert_eq!(check_block_receipts(&receipts, &root), Err(ReceiptError::RootMismatch));

    // Reordered leaves in the run, and blocks given out of order.
    let blocks = [checked(&honest)];
    let mut leaves = honest.leaves.clone();
    leaves.swap(3, 4);
    assert_eq!(check_leaves(&blocks, 0, 0, &leaves), Err(ReceiptError::LeafMismatch { position: 3 }));
    let first = block(0, 20);
    let second = block(first.leaves.len() as u32, 20);
    let leaves = [first.leaves.clone(), second.leaves.clone()].concat();
    let swapped = [checked(&second), checked(&first)];
    assert!(matches!(check_leaves(&swapped, 0, 0, &leaves), Err(ReceiptError::RecordSequence { .. })));
}

#[test]
fn a_repeated_or_invented_leaf_is_refused() {
    let honest = block(0, 150);
    let blocks = [checked(&honest)];
    let mut leaves = honest.leaves.clone();
    leaves.insert(8, leaves[7].clone());
    assert!(check_leaves(&blocks, 0, 0, &leaves).is_err());

    let mut leaves = honest.leaves.clone();
    let next = leaves.len() as u32;
    leaves.push(TreeLeaf { commitment: leaf_at(0, next), note: note_at(next) });
    assert_eq!(check_leaves(&blocks, 0, 0, &leaves), Err(ReceiptError::LeafInvented { position: next }));

    // A run starting past the receipts invents every leaf.
    assert_eq!(
        check_leaves(&blocks, 0, next, &leaves[next as usize..]),
        Err(ReceiptError::LeafInvented { position: next })
    );
    // A run that starts at the wrong position.
    assert_eq!(
        check_leaves(&blocks, 0, 5, &honest.leaves[6..]),
        Err(ReceiptError::LeafMismatch { position: 5 })
    );
    // The same block twice repeats its records.
    let twice = [checked(&honest), checked(&honest)];
    assert!(matches!(check_leaves(&twice, 0, 0, &honest.leaves), Err(ReceiptError::RecordSequence { .. })));
    // The run is for another tree index than the records.
    assert_eq!(check_leaves(&blocks, 1, 0, &honest.leaves), Err(ReceiptError::LeafInvented { position: 0 }));
}

#[test]
fn a_changed_marker_is_refused() {
    let honest = block(0, 150);
    let blocks = [checked(&honest)];
    let mut markers = honest.markers.clone();
    markers[9] = marker_at(1000);
    assert_eq!(check_markers(&blocks, &markers), Err(ReceiptError::MarkerMismatch { index: 9 }));
    let mut markers = honest.markers.clone();
    markers.swap(0, 1);
    assert_eq!(check_markers(&blocks, &markers), Err(ReceiptError::MarkerMismatch { index: 0 }));

    // In a receipt: the root no longer matches.
    let root = simple_receipts_root(&honest.receipts);
    let mut receipts = honest.receipts.clone();
    let marker = marker_at(1);
    let at = receipts[2].windows(32).position(|w| w == marker.as_bytes()).unwrap();
    receipts[2][at] ^= 1;
    assert_eq!(check_block_receipts(&receipts, &root), Err(ReceiptError::RootMismatch));
}

#[test]
fn an_invented_or_missing_marker_is_refused() {
    let honest = block(0, 150);
    let blocks = [checked(&honest)];
    let mut markers = honest.markers.clone();
    markers.push(marker_at(1000));
    assert_eq!(check_markers(&blocks, &markers), Err(ReceiptError::MarkerInvented { index: honest.markers.len() }));
    let mut markers = honest.markers.clone();
    markers.insert(3, marker_at(1000));
    assert_eq!(check_markers(&blocks, &markers), Err(ReceiptError::MarkerMismatch { index: 3 }));
    let mut markers = honest.markers.clone();
    markers.pop();
    assert_eq!(check_markers(&blocks, &markers), Err(ReceiptError::MarkerMissing { index: markers.len() }));
    let mut markers = honest.markers.clone();
    markers.remove(0);
    assert_eq!(check_markers(&blocks, &markers), Err(ReceiptError::MarkerMismatch { index: 0 }));
    // A commit has no marker to offer: the markers are the reveals' only.
    let commits_only = block(0, 2);
    assert_eq!(check_markers(&[checked(&commits_only)], &[marker_at(0)]), Err(ReceiptError::MarkerInvented { index: 0 }));
}

/// A block whose root is right but whose one receipt carries `logs`.
fn single(logs: &[Vec<u8>]) -> Result<CheckedBlock, ReceiptError> {
    let receipts = vec![receipt(Some(0x50), 1, 21_000, logs)];
    check_block_receipts(&receipts, &simple_receipts_root(&receipts))
}

#[test]
fn a_coin_log_off_the_layout_is_refused() {
    let commit_topic = k("ghost/commit-receipt/v1", &[]);
    let reveal_topic = k("ghost/reveal-receipt/v1", &[]);
    let commit_data = [0u8; 4 + 4 + 32 + 32 + NOTE_BYTES];
    let reveal_data = [0u8; 4 + 4 + 32 + NOTE_BYTES + 20 + 32];
    assert!(single(&[log(&COIN_TREE_ACCOUNT, &[commit_topic], &commit_data)]).is_ok());
    assert!(single(&[log(&COIN_TREE_ACCOUNT, &[reveal_topic, [9; 32]], &reveal_data)]).is_ok());

    let refused = [
        log(&COIN_TREE_ACCOUNT, &[commit_topic], &commit_data[1..]),
        log(&COIN_TREE_ACCOUNT, &[commit_topic], &[&commit_data[..], &[0]].concat()),
        log(&COIN_TREE_ACCOUNT, &[commit_topic, [9; 32]], &commit_data),
        log(&COIN_TREE_ACCOUNT, &[reveal_topic], &reveal_data),
        log(&COIN_TREE_ACCOUNT, &[reveal_topic, [9; 32], [9; 32]], &reveal_data),
        log(&COIN_TREE_ACCOUNT, &[reveal_topic, [9; 32]], &reveal_data[1..]),
        log(&COIN_TREE_ACCOUNT, &[reveal_topic, [9; 32]], &commit_data),
        log(&COIN_TREE_ACCOUNT, &[[9; 32]], &commit_data),
        log(&COIN_TREE_ACCOUNT, &[], &commit_data),
    ];
    for (i, bad) in refused.iter().enumerate() {
        let logs = [log(&OTHER_ADDRESS, &[], b""), bad.clone()];
        assert!(
            matches!(single(&logs), Err(ReceiptError::CoinLog { receipt: 0, log: 1, .. })),
            "case {i} is refused"
        );
    }

    // Any shape is fine at another address.
    assert_eq!(single(&[log(&OTHER_ADDRESS, &[commit_topic], b"x")]).unwrap().records(), &[]);

    // A failed receipt with a coin tree log.
    let receipts = vec![receipt(Some(0x50), 0, 21_000, &[log(&COIN_TREE_ACCOUNT, &[commit_topic], &commit_data)])];
    assert!(matches!(
        check_block_receipts(&receipts, &simple_receipts_root(&receipts)),
        Err(ReceiptError::CoinLog { .. })
    ));
}

#[test]
fn a_receipt_that_does_not_decode_is_refused() {
    let good = receipt(None, 1, 21_000, &[]);
    let typed = receipt(Some(0x50), 1, 21_000, &[]);
    let short_bloom = [vec![0x50], rlp_list(&[rlp_uint(1), rlp_uint(1), rlp_bytes(&[0; 255]), rlp_list(&[])])].concat();
    let bad_status = rlp_list(&[rlp_uint(2), rlp_uint(1), rlp_bytes(&[0; 256]), rlp_list(&[])]);
    let three_fields = rlp_list(&[rlp_uint(1), rlp_uint(1), rlp_bytes(&[0; 256])]);
    let short_address = rlp_list(&[
        rlp_uint(1),
        rlp_uint(1),
        rlp_bytes(&[0; 256]),
        rlp_list(&[log(&[0x11; 19], &[], b"")]),
    ]);
    let cases = [
        vec![],
        vec![0x80],
        vec![0x00, 0xc0],
        [&good[..], &[0]].concat(),
        typed[..typed.len() - 1].to_vec(),
        short_bloom,
        bad_status,
        three_fields,
        short_address,
    ];
    for (i, bad) in cases.iter().enumerate() {
        let receipts = vec![good.clone(), bad.clone()];
        assert!(
            matches!(
                check_block_receipts(&receipts, &simple_receipts_root(&receipts)),
                Err(ReceiptError::Receipt { receipt: 1, .. })
            ),
            "case {i} is refused"
        );
    }
}
