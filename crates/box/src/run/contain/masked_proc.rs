//! The box's half of a masked-`/proc` refusal: name the `box.toml` key that opts in.
//!
//! The containment crate names the cause in its own vocabulary (`ProcessInfoMode::AllowAll`). This
//! reads the same mount table to decide, rather than parsing that text, because the agent's stderr
//! is the operator's terminal and never reaches the box. The parser is a deliberate copy of
//! `masked_proc_points` in the containment crate's Linux view: that one is private to a module this
//! crate cannot reach.

use std::path::Path;

use crate::error::SetupStage;

/// What a masked-`/proc` refusal gains on the box's side.
pub(crate) const HINT: &str = "set [containment] private_proc = false in box.toml to reuse this \
                               container's /proc; the workload can then list the container's \
                               processes";

/// The detail an `Apply` failure should carry, with the hint added when this box asked for a
/// private `/proc` and the host masks it. Every other failure passes through unchanged.
pub(crate) fn hint(stage: SetupStage, detail: Option<String>, shares_proc: bool) -> Option<String> {
    if !cfg!(target_os = "linux") {
        return detail;
    }
    let table = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    hint_with(stage, detail, shares_proc, &table)
}

fn hint_with(
    stage: SetupStage,
    detail: Option<String>,
    shares_proc: bool,
    table: &str,
) -> Option<String> {
    if stage != SetupStage::Apply || shares_proc || !host_masks_proc(table) {
        return detail;
    }
    Some(match detail {
        Some(detail) => format!("{detail}; {HINT}"),
        None => HINT.to_string(),
    })
}

/// Whether a mount table carries a mount strictly under `/proc`: a container runtime's masks.
fn host_masks_proc(table: &str) -> bool {
    table
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(Path::new)
        .any(|point| point != Path::new("/proc") && point.starts_with("/proc"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASKED: &str = "proc /proc proc rw 0 0\ntmpfs /proc/kcore tmpfs rw 0 0\n";
    const CLEAN: &str = "proc /proc proc rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n";

    #[test]
    fn a_masked_table_is_recognised_and_a_clean_one_is_not() {
        assert!(host_masks_proc(MASKED));
        assert!(!host_masks_proc(CLEAN));
        assert!(!host_masks_proc("tmpfs /procfoo tmpfs rw 0 0\n"));
    }

    #[test]
    fn the_hint_is_added_only_to_an_apply_failure_of_a_private_proc_box_on_a_masked_host() {
        let with = |stage, detail: Option<&str>, shares, table| {
            hint_with(stage, detail.map(str::to_string), shares, table)
        };
        let added = with(SetupStage::Apply, Some("x"), false, MASKED).unwrap();
        assert!(added.starts_with("x; "), "{added}");
        assert!(added.ends_with(HINT), "{added}");
        assert_eq!(
            with(SetupStage::Apply, None, false, MASKED).as_deref(),
            Some(HINT)
        );
        assert_eq!(
            with(SetupStage::Apply, Some("x"), true, MASKED).as_deref(),
            Some("x")
        );
        assert_eq!(
            with(SetupStage::Apply, Some("x"), false, CLEAN).as_deref(),
            Some("x")
        );
        assert_eq!(
            with(SetupStage::Exec, Some("x"), false, MASKED).as_deref(),
            Some("x")
        );
    }

    #[test]
    fn the_hint_names_the_key_exactly() {
        assert_eq!(
            HINT,
            "set [containment] private_proc = false in box.toml to reuse this container's /proc; \
             the workload can then list the container's processes"
        );
    }
}
