//! Owned handle wrappers around `aws-lc-sys` FFI types.
//!
//! Each newtype's `Drop` calls the correct `*_free` so the rest of the
//! codebase never deals with raw pointers. `unsafe` is confined to this
//! file and the per-primitive modules built on top of it; every `unsafe`
//! block carries a `// SAFETY:` comment naming the invariant.

use std::ptr::NonNull;

use aws_lc_sys as aws;

/// Owned `SSL_CTX*`. Thread-safe per AWS-LC documentation once
/// initialised, so `Send + Sync` is sound.
///
/// `Clone` increments the reference count via `SSL_CTX_up_ref` so that
/// multiple I/O workers can share the same underlying `SSL_CTX` without
/// an extra `Arc` wrapper.
pub struct SslCtx(NonNull<aws::SSL_CTX>);

// SAFETY: SSL_CTX is documented thread-safe in AWS-LC.
unsafe impl Send for SslCtx {}
// SAFETY: SSL_CTX is documented thread-safe in AWS-LC.
unsafe impl Sync for SslCtx {}

impl Clone for SslCtx {
    fn clone(&self) -> Self {
        // SAFETY: self.0 is a valid SSL_CTX*; up_ref increments the
        // internal refcount and always returns 1 (AWS-LC invariant).
        let rc = unsafe { aws::SSL_CTX_up_ref(self.0.as_ptr()) };
        assert_eq!(rc, 1, "SSL_CTX_up_ref failed");
        Self(self.0)
    }
}

impl SslCtx {
    /// Wrap a raw pointer returned by `SSL_CTX_new`. Returns `None` on
    /// null.
    ///
    /// # Safety
    /// `p` must be a valid `SSL_CTX*` whose ownership is transferred to
    /// the returned `SslCtx` (it will be freed on drop).
    pub unsafe fn from_raw(p: *mut aws::SSL_CTX) -> Option<Self> {
        NonNull::new(p).map(Self)
    }

    pub fn as_ptr(&self) -> *mut aws::SSL_CTX {
        self.0.as_ptr()
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid pointer from SSL_CTX_new and is
        // exclusively owned by this struct.
        unsafe { aws::SSL_CTX_free(self.0.as_ptr()) };
    }
}

/// Owned `SSL*`. Bound to a single connection; **not** `Sync`.
pub struct Ssl(NonNull<aws::SSL>);

// SAFETY: SSL is safe to move between threads as long as it's accessed
// from one thread at a time. We never hand the inner pointer to another
// thread while still holding our own reference.
unsafe impl Send for Ssl {}

impl Ssl {
    /// # Safety
    /// `p` must be a valid `SSL*` whose ownership transfers to the
    /// returned `Ssl`.
    pub unsafe fn from_raw(p: *mut aws::SSL) -> Option<Self> {
        NonNull::new(p).map(Self)
    }

    pub fn as_ptr(&self) -> *mut aws::SSL {
        self.0.as_ptr()
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid pointer from SSL_new and exclusively
        // owned by this struct.
        unsafe { aws::SSL_free(self.0.as_ptr()) };
    }
}
