//! `--fetch` (DESIGN.md §18.7): getting a revocation record with libcurl.
//!
//! Only `http` and `https`, redirects included: redirects are followed here,
//! one hop at a time, so each URL is checked before it is requested. A
//! record is checked by its signatures, so TLS adds privacy, not integrity:
//! on a certificate error the request is retried without verifying the
//! certificate, with a warning.

use curl::easy::Easy;
use std::time::Duration;

/// Largest response accepted.
const MAX_SIZE: usize = 16 << 20;
/// Most redirects followed.
const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(10);

enum Response {
    Body(Vec<u8>),
    Redirect(String),
    /// Any other HTTP status.
    Status(u32),
}

/// The body at `url`.
pub fn get(url: &str) -> Result<Vec<u8>, String> {
    let mut url = url.to_owned();
    let mut verify = true;
    let mut hops = 0;
    loop {
        check_scheme(&url)?;
        match request(&url, verify) {
            Ok(Response::Body(body)) => return Ok(body),
            Ok(Response::Status(code)) => return Err(format!("HTTP status {code}")),
            Ok(Response::Redirect(next)) => {
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return Err(format!("more than {MAX_REDIRECTS} redirects"));
                }
                url = next;
            }
            Err(e) if verify && (e.is_peer_failed_verification() || e.is_ssl_cacert()) => {
                crate::warn(format!(
                    "{url}: the TLS certificate does not verify ({}); fetching without \
                     checking it, since writ checks the record's signatures",
                    e.description()
                ));
                verify = false;
            }
            Err(e) if e.is_write_error() => {
                return Err(format!("larger than {} MiB", MAX_SIZE >> 20));
            }
            Err(e) => return Err(e.description().to_owned()),
        }
    }
}

fn check_scheme(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        if curl::Version::get().ssl_version().is_none() {
            return Err(
                "this writ was built without TLS support; get the record another way \
                 and give it with --in"
                    .into(),
            );
        }
        Ok(())
    } else if lower.starts_with("http://") {
        Ok(())
    } else {
        Err("only http and https URLs are fetched".into())
    }
}

fn request(url: &str, verify: bool) -> Result<Response, curl::Error> {
    let mut easy = Easy::new();
    easy.url(url)?;
    easy.follow_location(false)?;
    easy.timeout(TIMEOUT)?;
    easy.connect_timeout(TIMEOUT)?;
    easy.max_filesize(MAX_SIZE as u64)?;
    easy.useragent(concat!("writ/", env!("CARGO_PKG_VERSION")))?;
    if !verify {
        easy.ssl_verify_peer(false)?;
        easy.ssl_verify_host(false)?;
    }
    let mut body = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            if body.len() + data.len() > MAX_SIZE {
                return Ok(0); // libcurl stops with a write error
            }
            body.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }
    let code = easy.response_code()?;
    if (300..400).contains(&code)
        && let Some(next) = easy.redirect_url()?
    {
        return Ok(Response::Redirect(next.to_owned()));
    }
    Ok(if code == 200 {
        Response::Body(body)
    } else {
        Response::Status(code)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_http_and_https() {
        assert!(check_scheme("http://example.org/r").is_ok());
        assert!(check_scheme("HTTP://example.org/r").is_ok());
        for bad in [
            "file:///etc/passwd",
            "ftp://x/r",
            "gopher://x",
            "example.org",
        ] {
            assert!(check_scheme(bad).is_err(), "{bad}");
        }
    }
}
