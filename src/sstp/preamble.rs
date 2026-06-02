//! SSTP HTTPS layer (MS-SSTP §3.2.4.1 / §4.1).
//!
//! Before any SSTP framing flows, the client opens an
//! `SSTP_DUPLEX_POST` "request" to a well-known URI and waits for a
//! `200 OK`. After that exchange the same TCP/TLS connection carries
//! raw SSTP control / data packets in both directions; there is no
//! HTTP body — both `Content-Length` headers are the lie
//! `ULONGLONG_MAX` and exist purely to keep generic HTTP intermediaries
//! from buffering or framing the stream.
//!
//! This module is responsible for two operations only:
//!   1. Read the client's request line + headers, validate them
//!      against the spec, and return the parsed metadata
//!      (correlation GUID, if any).
//!   2. Write back the canned `HTTP/1.1 200` response.
//!
//! Everything past the empty header line belongs to the SSTP framing
//! layer (`crate::sstp::frame`). Nothing in this module touches body
//! bytes; if the client pipelines an SSTP frame into the same TCP
//! segment as the request, the SSTP state machine in the caller has
//! to handle that (it must, anyway, since TLS records and TCP segments
//! don't align with SSTP frames).

use std::fmt::Write as _;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Well-known URI the client posts to. Spec quotes the literal in
/// §3.2.4.1; the GUID is fixed across all deployments.
pub const SSTP_URI: &str = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/";

/// `SSTP_DUPLEX_POST` is the HTTP method (not a standard verb).
pub const SSTP_METHOD: &str = "SSTP_DUPLEX_POST";

/// `ULONGLONG_MAX`, as a decimal string. Both request and response
/// headers carry exactly this value.
pub const ULONGLONG_MAX_STR: &str = "18446744073709551615";

/// Cap on the size of the request-line + header block. RFC 7230 §3.2.5
/// gives implementations broad latitude; 4 KiB is comfortably larger
/// than any legitimate `SSTP_DUPLEX_POST` (which is essentially a fixed
/// template plus a 38-byte GUID) and small enough that a malicious
/// peer can't make us buffer megabytes before we cut them off.
pub const MAX_HEADER_BYTES: usize = 4096;

/// Parsed result of a successful preamble exchange.
#[derive(Debug, Default, Clone)]
pub struct Preamble {
    /// Value of the `SSTPCORRELATIONID` request header, if present.
    /// The spec recommends but does not require this — the server is
    /// expected to log it verbatim against the session so operators
    /// can cross-reference client- and server-side traces.
    pub correlation_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum PreambleError {
    /// Underlying TLS / TCP read failed.
    #[error("I/O reading HTTP preamble: {0}")]
    Io(#[from] std::io::Error),
    /// Client closed the connection before sending a complete header
    /// block.
    #[error("peer closed mid-preamble after {0} bytes")]
    Eof(usize),
    /// Header block exceeded [`MAX_HEADER_BYTES`] without an empty
    /// line.
    #[error("HTTP header block exceeded {MAX_HEADER_BYTES} bytes")]
    TooLarge,
    /// Bad request line (method / URI / version mismatch) or an
    /// invalid / unsupported header value. The contained `&'static str`
    /// is meant for logs and the eventual `400 Bad Request` response
    /// body; it must not echo attacker-controlled bytes back.
    #[error("malformed SSTP preamble: {0}")]
    Bad(&'static str),
}

/// Read and validate the client's `SSTP_DUPLEX_POST` request, then
/// write back the canned `HTTP/1.1 200` response. On error,
/// [`write_error_response`] is *not* called automatically — the
/// caller decides whether to bother sending a `400` before tearing
/// down (we shouldn't, for I/O errors; we should, for protocol
/// errors).
pub async fn handshake<S>(stream: &mut S) -> Result<Preamble, PreambleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let raw = read_header_block(stream).await?;
    let preamble = parse_request(&raw)?;
    write_ok_response(stream).await?;
    Ok(preamble)
}

/// Read bytes from `stream` until the CRLF-CRLF header terminator,
/// returning everything up to and including it. Bounded by
/// [`MAX_HEADER_BYTES`].
async fn read_header_block<S>(stream: &mut S) -> Result<Vec<u8>, PreambleError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(PreambleError::Eof(buf.len()));
        }
        if buf.len() + n > MAX_HEADER_BYTES {
            return Err(PreambleError::TooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
        if find_header_terminator(&buf).is_some() {
            return Ok(buf);
        }
    }
}

/// Locate the `\r\n\r\n` sequence terminating an HTTP header block.
/// Returns the index of the first byte *after* the terminator.
fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse a header block: validate the request line, walk the header
/// lines, capture the correlation GUID.
///
/// Accepts only the strict spec form: `SSTP_DUPLEX_POST <URI>
/// HTTP/1.1\r\n`, headers as `Name: Value\r\n`, terminated by an
/// empty CRLF line. Header names are case-insensitive per RFC 7230
/// §3.2; values are trimmed of leading/trailing whitespace.
pub fn parse_request(raw: &[u8]) -> Result<Preamble, PreambleError> {
    // ASCII-only by spec; reject any byte > 0x7F so log lines and
    // error messages stay safe to print.
    if raw.iter().any(|&b| b >= 0x80) {
        return Err(PreambleError::Bad("non-ASCII byte in header block"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| PreambleError::Bad("non-UTF-8 header"))?;
    let mut lines = text.split("\r\n");

    let request_line = lines.next().ok_or(PreambleError::Bad("empty request"))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(PreambleError::Bad("missing method"))?;
    let uri = parts.next().ok_or(PreambleError::Bad("missing URI"))?;
    let version = parts.next().ok_or(PreambleError::Bad("missing version"))?;
    if parts.next().is_some() {
        return Err(PreambleError::Bad("trailing tokens on request line"));
    }
    if method != SSTP_METHOD {
        return Err(PreambleError::Bad("method must be SSTP_DUPLEX_POST"));
    }
    if uri != SSTP_URI {
        return Err(PreambleError::Bad("URI must be the SSTP well-known path"));
    }
    if version != "HTTP/1.1" {
        return Err(PreambleError::Bad("HTTP version must be 1.1"));
    }

    let mut content_length_ok = false;
    let mut correlation_id = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(PreambleError::Bad("header missing colon"))?;
        let value = value.trim();
        // ASCII case-insensitive compare without allocating.
        if name.eq_ignore_ascii_case("content-length") {
            if value != ULONGLONG_MAX_STR {
                return Err(PreambleError::Bad("Content-Length must be ULONGLONG_MAX"));
            }
            content_length_ok = true;
        } else if name.eq_ignore_ascii_case("sstpcorrelationid") {
            // Cap the captured length defensively; legitimate GUIDs
            // are 38 chars with braces. Anything wildly longer is
            // either junk or an exfil attempt against our log
            // pipeline.
            if value.len() <= 64 {
                correlation_id = Some(value.to_string());
            }
        }
        // Other headers (`Host`, `User-Agent`, ...) are accepted and
        // ignored — the spec doesn't require us to validate them.
    }
    if !content_length_ok {
        return Err(PreambleError::Bad("missing Content-Length header"));
    }

    Ok(Preamble { correlation_id })
}

/// Send the canned `HTTP/1.1 200` response. The `Date:` header is
/// formatted as RFC 7231 §7.1.1.1 IMF-fixdate from the current system
/// clock; everything else is constant.
pub async fn write_ok_response<S>(stream: &mut S) -> Result<(), PreambleError>
where
    S: AsyncWrite + Unpin,
{
    let mut resp = String::with_capacity(192);
    let _ = write!(
        resp,
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {ULONGLONG_MAX_STR}\r\n\
         Server: Microsoft-HTTPAPI/2.0\r\n\
         Date: {}\r\n\
         \r\n",
        imf_fixdate_now()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Best-effort `400 Bad Request` for protocol errors. Best-effort
/// because the connection is about to be torn down — if the write
/// fails, the caller drops the stream anyway.
pub async fn write_error_response<S>(stream: &mut S) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let resp = b"HTTP/1.1 400 Bad Request\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n";
    stream.write_all(resp).await?;
    stream.flush().await
}

/// Format the current UTC time as RFC 7231 §7.1.1.1 IMF-fixdate
/// (e.g. `Thu, 09 Nov 2006 00:51:09 GMT`). Implemented locally to
/// avoid pulling in `chrono` / `time` for a single header line.
fn imf_fixdate_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_imf_fixdate(now)
}

/// Convert a UNIX timestamp into the IMF-fixdate textual form.
/// Pure function so it's unit-testable without poking the clock.
fn format_imf_fixdate(unix_secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    const DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTH_NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    // Decompose unix_secs into (y, m, d, hh, mm, ss). Algorithm
    // from Howard Hinnant's "date" algorithm
    // (http://howardhinnant.github.io/date_algorithms.html); avoids
    // any C library / floating point and is exact for the entire
    // representable range.
    let days = i64::try_from(unix_secs / SECS_PER_DAY).unwrap_or(0);
    let secs_of_day = unix_secs % SECS_PER_DAY;

    // Civil-from-days, with 1970-01-01 as day 0.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    // `doe` is in [0, 146096] by construction once `era` is subtracted out.
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y_civil = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y_civil + 1 } else { y_civil };

    let hh = secs_of_day / 3600;
    let mm = (secs_of_day / 60) % 60;
    let ss = secs_of_day % 60;

    // Day-of-week: 1970-01-01 was a Thursday (4).
    let dow = (days.rem_euclid(7) + 4) % 7;

    format!(
        "{day_name}, {d:02} {mon_name} {y:04} {hh:02}:{mm:02}:{ss:02} GMT",
        day_name = DAY_NAMES[usize::try_from(dow).unwrap_or(0)],
        mon_name = MONTH_NAMES[usize::try_from(m - 1).unwrap_or(0)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn parses_canonical_request() {
        let req = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                    Host: vpn.example.com\r\n\
                    SSTPCORRELATIONID: {12345678-1234-1234-1234-1234567890AB}\r\n\
                    Content-Length: 18446744073709551615\r\n\
                    \r\n";
        let p = parse_request(req).expect("parse");
        assert_eq!(
            p.correlation_id.as_deref(),
            Some("{12345678-1234-1234-1234-1234567890AB}")
        );
    }

    #[test]
    fn rejects_wrong_method() {
        let req = b"POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                    Content-Length: 18446744073709551615\r\n\r\n";
        assert!(matches!(parse_request(req), Err(PreambleError::Bad(_))));
    }

    #[test]
    fn rejects_wrong_uri() {
        let req = b"SSTP_DUPLEX_POST /wrong HTTP/1.1\r\n\
                    Content-Length: 18446744073709551615\r\n\r\n";
        assert!(matches!(parse_request(req), Err(PreambleError::Bad(_))));
    }

    #[test]
    fn rejects_wrong_version() {
        let req = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.0\r\n\
                    Content-Length: 18446744073709551615\r\n\r\n";
        assert!(matches!(parse_request(req), Err(PreambleError::Bad(_))));
    }

    #[test]
    fn rejects_missing_content_length() {
        let req = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                    Host: x\r\n\r\n";
        assert!(matches!(parse_request(req), Err(PreambleError::Bad(_))));
    }

    #[test]
    fn rejects_wrong_content_length() {
        let req = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                    Content-Length: 100\r\n\r\n";
        assert!(matches!(parse_request(req), Err(PreambleError::Bad(_))));
    }

    #[test]
    fn rejects_non_ascii() {
        let mut req = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                        Content-Length: 18446744073709551615\r\n\r\n"
            .to_vec();
        req.insert(20, 0xC3);
        assert!(matches!(parse_request(&req), Err(PreambleError::Bad(_))));
    }

    #[test]
    fn imf_fixdate_known_value() {
        // 2006-11-09 00:51:09 UTC == 1163033469. Same example as the
        // spec's response template in §4.1.
        assert_eq!(
            format_imf_fixdate(1_163_033_469),
            "Thu, 09 Nov 2006 00:51:09 GMT"
        );
        // 1970-01-01 epoch.
        assert_eq!(format_imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[tokio::test]
    async fn handshake_writes_200() {
        let (mut client, mut server) = duplex(4096);
        // Spawn the server-side handshake.
        let h = tokio::spawn(async move {
            let p = handshake(&mut server).await.expect("server handshake");
            (p, server)
        });
        // Client sends the canonical request and reads the response.
        let req = b"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n\
                    Host: vpn\r\n\
                    Content-Length: 18446744073709551615\r\n\r\n";
        client.write_all(req).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp}");
        assert!(resp.contains("Content-Length: 18446744073709551615\r\n"));
        assert!(resp.contains("Server: Microsoft-HTTPAPI/2.0\r\n"));
        let (p, _server) = h.await.unwrap();
        assert!(p.correlation_id.is_none());
    }
}
