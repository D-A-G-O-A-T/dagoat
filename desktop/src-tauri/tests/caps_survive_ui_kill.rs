//! INV-9. The caps are the daemon's, not the window's.
//!
//! The UI process is simulated by writing the limits file and then dropping every
//! in-process handle -- exactly what a forced kill on the shell leaves behind. What
//! must survive is the file and the clamp, because that is all the sidecar reads.
//!
//! And the clamp is only half of it: the ceiling and the throttle are inside the
//! SIGNED consent preimage, so a control this window moves upward cannot raise the
//! number the daemon enforces. A cap a killed UI can defeat is not a cap; neither is
//! one a hand-edited file can raise.
//!
//! Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
//! rule" spec, §1 and §8.

use dagoat_lib::proxy::limits::{
    self, ProxyLimits, ScheduleWindow, BYTES_PER_GB, MAX_DAILY_CAP_GB, MAX_THROTTLE_KBPS,
};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("goat-proxy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Mutations this detects: caps held in React state, or a store the webview owns --
/// either of which a killed window takes with it.
#[test]
fn caps_survive_ui_kill() {
    let dir = scratch("caps-survive");
    let written = limits::clamp(ProxyLimits {
        enabled: true,
        daily_cap_gb: 3,
        throttle_kbps: 512,
        windows: vec![ScheduleWindow {
            start_min_local: 60,
            end_min_local: 120,
            days_mask: 0x7f,
        }],
        schema: 1,
    });
    limits::store(&dir, &written).unwrap();

    // "Kill the UI": everything in-process goes away. Only the file remains.
    drop(written.clone());

    let reread = limits::load(&dir).expect("the daemon must still find the caps");
    assert_eq!(reread, written);
    assert_eq!(reread.daily_cap_gb, 3);
    assert_eq!(reread.throttle_kbps, 512);
    assert!(
        !limits::admits(&reread, 59),
        "schedule must still close outside the window"
    );
    assert!(limits::admits(&reread, 61));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mutations this detects: dropping either clamp from `load`. A clamp applied only on
/// write is no clamp at all -- the file is the interface, and anything with the user's
/// privileges can write it.
#[test]
fn a_hand_edited_limits_file_cannot_raise_the_ceiling() {
    let dir = scratch("hand-edited");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        limits::limits_path(&dir),
        "{\"enabled\":true,\"daily_cap_gb\":4294967295,\"throttle_kbps\":4294967295}",
    )
    .unwrap();
    let reread = limits::load(&dir).expect("a hostile file must still parse into a clamped value");
    assert_eq!(reread.daily_cap_gb, MAX_DAILY_CAP_GB);
    assert_eq!(reread.throttle_kbps, MAX_THROTTLE_KBPS);
    // POSITIVE CONTROL: the same reader passes an in-range file through untouched, so
    // the two assertions above are not a reader that returns the maximum for anything.
    std::fs::write(
        limits::limits_path(&dir),
        "{\"enabled\":true,\"daily_cap_gb\":9,\"throttle_kbps\":700}",
    )
    .unwrap();
    let sane = limits::load(&dir).unwrap();
    assert_eq!(sane.daily_cap_gb, 9);
    assert_eq!(sane.throttle_kbps, 700);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mutations this detects: a parse failure treated as "no limits configured" and then
/// as "no limit". Unreadable must fall back to the DEFAULT, and the default is off.
#[test]
fn a_truncated_limits_file_falls_back_to_the_default_not_to_unlimited() {
    let dir = scratch("truncated");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(limits::limits_path(&dir), "{\"enabled\":tru").unwrap();
    assert!(limits::load(&dir).is_none());
    let fallback = ProxyLimits::default();
    assert!(!fallback.enabled);
    assert_eq!(fallback.daily_cap_gb, limits::DEFAULT_DAILY_CAP_GB);
    assert_eq!(fallback.throttle_kbps, limits::DEFAULT_THROTTLE_KBPS);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Mutations this detects: `max` for `min` in the effective ceiling, or the ceiling
/// read straight from the limits file. Raising the control past what the operator
/// signed must move the daemon's ceiling by nothing at all -- otherwise the signature
/// binds a number that is not the one in force.
#[test]
fn a_cap_raised_by_the_ui_alone_does_not_raise_the_daemons_ceiling() {
    let dir = scratch("ui-cannot-raise");
    let consented = 5 * BYTES_PER_GB;

    // The window writes the largest cap the control allows.
    limits::store(
        &dir,
        &limits::clamp(ProxyLimits {
            enabled: true,
            daily_cap_gb: MAX_DAILY_CAP_GB,
            ..Default::default()
        }),
    )
    .unwrap();
    let reread = limits::load(&dir).unwrap();
    assert_eq!(reread.daily_cap_gb, MAX_DAILY_CAP_GB);
    assert_eq!(
        limits::effective_ceiling_bytes(consented, &reread),
        consented,
        "the ceiling in force is the one that was signed"
    );

    // POSITIVE CONTROL: lowering it DOES take effect, so the assertion above is not a
    // function that ignores its second argument.
    limits::store(
        &dir,
        &limits::clamp(ProxyLimits {
            enabled: true,
            daily_cap_gb: 2,
            ..Default::default()
        }),
    )
    .unwrap();
    let lowered = limits::load(&dir).unwrap();
    assert_eq!(
        limits::effective_ceiling_bytes(consented, &lowered),
        2 * BYTES_PER_GB
    );
    let _ = std::fs::remove_dir_all(&dir);
}
