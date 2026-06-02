//! Build script: emit `VERGEN_GIT_SHA` (short) and `VERGEN_GIT_COMMIT_DATE`
//! so the binary's `--version` can report the source revision in addition
//! to the crate version.

use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let git2 = Git2Builder::default()
        .sha(true) // short SHA (VERGEN_GIT_SHA)
        .commit_date(true) // YYYY-MM-DD (VERGEN_GIT_COMMIT_DATE)
        .build()?;

    // Note: `.idempotent()` is intentionally NOT set — it would blank
    // `VERGEN_GIT_COMMIT_DATE` for reproducibility. `option_env!` in the
    // consumer handles the "not in a git checkout" case at runtime by
    // falling back to the bare crate version.
    Emitter::default().add_instructions(&git2)?.emit()?;

    Ok(())
}
