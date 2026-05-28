//! RNG wrapper around `RAND_bytes`.

use std::mem::MaybeUninit;

use aws_lc_sys as aws;

/// Fill `out` with cryptographically secure random bytes.
///
/// After returning, every element of `out` is fully initialised.
///
/// Panics if the AWS-LC RNG is unusable; for a long-running daemon this is
/// an unrecoverable initialisation failure that the process can't continue
/// past.
pub fn fill_bytes(out: &mut [MaybeUninit<u8>]) {
    if out.is_empty() {
        return;
    }
    // SAFETY: MaybeUninit<u8> has the same layout as u8; RAND_bytes writes
    // exactly `out.len()` bytes, fully initialising every element.
    let rc = unsafe { aws::RAND_bytes(out.as_mut_ptr().cast::<u8>(), out.len()) };
    assert_eq!(rc, 1, "RAND_bytes failed; AWS-LC RNG unusable");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_blocks() {
        let mut a = [MaybeUninit::uninit(); 32];
        let mut b = [MaybeUninit::uninit(); 32];
        fill_bytes(&mut a);
        fill_bytes(&mut b);
        // SAFETY: fill_bytes fully initialises every element.
        let a = unsafe { a.map(|x| x.assume_init()) };
        let b = unsafe { b.map(|x| x.assume_init()) };
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn empty_is_noop() {
        fill_bytes(&mut []);
    }
}
