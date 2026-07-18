use std::fs;
use std::path::PathBuf;

const REQUIRED_CHECK_IDS: &[&str] = &[
    "BND-01", "BND-02", "BND-03", "BND-04", "MSG-01", "MSG-02", "MSG-03", "MSG-04", "OT-01",
    "OT-02", "OT-03", "OT-04", "OT-05", "OT-06", "MTA-01", "MTA-02", "TRI-01", "TRI-02", "TRI-03",
    "TRI-04", "TRI-05", "TRI-06", "TRI-07", "TRI-08", "TRI-09", "TRI-10", "TRI-11", "PRE-01",
    "PRE-02", "PRE-03", "PRE-04", "PRE-05", "PRE-06", "RER-01", "RER-02", "RER-03", "RER-04",
    "RER-05", "SIG-01", "SIG-02", "SIG-03", "SIG-04", "SIG-05", "USE-01", "ABT-01", "ABT-02",
    "ABT-03",
];

fn inventory_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../router-ab-ecdsa-presign/specs/upstream-check-inventory.md")
}

#[test]
fn upstream_check_inventory_has_the_complete_fixed_path_index() {
    let inventory = fs::read_to_string(inventory_path()).expect("read upstream check inventory");

    for id in REQUIRED_CHECK_IDS {
        let expected_cell = format!("`{id}`");
        let row_count = inventory
            .lines()
            .filter_map(|line| line.split('|').nth(1))
            .map(str::trim)
            .filter(|cell| *cell == expected_cell)
            .count();
        assert_eq!(row_count, 1, "missing or duplicate inventory row {id}");
    }

    assert!(!inventory.contains("TBD"));
    assert!(!inventory.contains("TODO"));
    assert!(inventory.contains("`OT-06` is the sole known behavioral mismatch"));
    assert!(inventory.contains("`A-OT-CORRECTED`"));
}
