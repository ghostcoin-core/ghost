//! The results page of the recursion layers, docs/scale/layers-results.md,
//! names the machine its figures were measured on, labels them measured,
//! compares the permutation cost with both thresholds of the design and
//! records the permutation table's real column count beside the modeled 451.

const PAGE: &str = include_str!("../../docs/scale/layers-results.md");

fn line_starting(prefix: &str) -> &'static str {
    PAGE.lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("the page has no line starting {prefix:?}"))
}

#[test]
fn the_page_names_the_machine() {
    let machine = line_starting("Machine:");
    assert!(machine.contains("measured"), "{machine}");
    assert!(machine.contains("cores"), "the machine line gives the core count: {machine}");
    assert!(machine.contains("GiB"), "the machine line gives the memory: {machine}");
    assert!(machine.contains("hostname"), "an unnamed VM is named by hostname: {machine}");
}

#[test]
fn the_permutation_cost_is_measured_and_compared_with_both_thresholds() {
    let cost = line_starting("Permutation cost:");
    assert!(cost.contains("measured"), "{cost}");
    assert!(cost.contains("ns per permutation"), "{cost}");
    for threshold in ["93 ns", "122 ns"] {
        let line = PAGE
            .lines()
            .find(|l| l.contains(threshold) && (l.contains("met") || l.contains("missed")))
            .unwrap_or_else(|| panic!("no comparison with the {threshold} threshold"));
        assert!(line.contains("measured") || line.contains("modeled"), "{line}");
    }
}

#[test]
fn the_page_records_the_real_column_count_beside_the_modeled_one() {
    let columns = line_starting("Permutation columns:");
    let real = ghost_proofs::layers::POSEIDON2_PERMUTATION_COLUMNS.to_string();
    assert!(columns.contains(&real), "{columns}");
    assert!(columns.contains("451"), "{columns}");
}

#[test]
fn every_layer_stage_is_measured_or_not_yet_established() {
    for stage in ["Batch:", "Root:", "Shrink:"] {
        let line = line_starting(stage);
        assert!(line.contains("measured") || line.contains("not yet established"), "{line}");
    }
    assert!(PAGE.contains("128 GiB"), "the page compares with the machine ceiling");
}
