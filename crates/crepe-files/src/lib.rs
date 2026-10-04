//! Bounded metadata/hash extraction for the first length-delimited HTTP body.
//! Body bytes are hashed incrementally and never retained or written to disk.
use crepe_core::{Error, Result};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub size: u64,
    pub sha256: String,
    pub mime: Option<String>,
}
#[derive(Debug)]
pub struct HttpFile {
    header: Vec<u8>,
    remaining: Option<u64>,
    size: u64,
    hash: Sha256,
    mime: Option<String>,
    done: bool,
    response_allowed: bool,
}
impl Default for HttpFile {
    fn default() -> Self {
        Self {
            header: Vec::new(),
            remaining: None,
            size: 0,
            hash: Sha256::new(),
            mime: None,
            done: false,
            response_allowed: false,
        }
    }
}
fn error(message: &str) -> Error {
    Error::new("CREPE-FILE-001", message)
}
impl HttpFile {
    pub fn allow_response(&mut self, allowed: bool) {
        self.response_allowed = allowed;
    }
    pub fn buffered_bytes(&self) -> usize {
        self.header.capacity()
    }
    pub fn incomplete(&self) -> bool {
        self.remaining.is_some_and(|n| n > 0)
    }
    fn stop(&mut self) {
        self.done = true;
        self.header = Vec::new();
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<Metadata>> {
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.stop();
            self.remaining = None;
        }
        result
    }
    fn push_inner(&mut self, mut bytes: &[u8]) -> Result<Option<Metadata>> {
        if self.done {
            return Ok(None);
        }
        if self.remaining.is_none() {
            // Keep only the header. A single large TCP segment must not duplicate its body.
            while let Some((&byte, tail)) = bytes.split_first() {
                bytes = tail;
                self.header.push(byte);
                if self.header.len() == 1 && byte == b'H' && !self.response_allowed {
                    self.stop();
                    return Ok(None);
                }
                if self.header.len() <= 5 {
                    let prefix = &self.header;
                    if !b"HTTP/".starts_with(prefix)
                        && !b"POST ".starts_with(prefix)
                        && !b"PUT ".starts_with(prefix)
                        && !prefix.starts_with(b"PUT ")
                    {
                        self.stop();
                        return Ok(None);
                    }
                }
                if self.header.len() > 65536 {
                    self.stop();
                    return Err(error("HTTP file header exceeds 64 KiB"));
                }
                if self.header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            if !self.header.ends_with(b"\r\n\r\n") {
                return Ok(None);
            }
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let parsed_headers = if self.header.starts_with(b"HTTP/") {
                let mut response = httparse::Response::new(&mut headers);
                response
                    .parse(&self.header)
                    .map_err(|_| error("invalid HTTP response header"))?;
                if response
                    .code
                    .is_some_and(|n| n < 200 || n == 204 || n == 304)
                {
                    self.stop();
                    return Ok(None);
                }
                response.headers
            } else {
                let mut request = httparse::Request::new(&mut headers);
                request
                    .parse(&self.header)
                    .map_err(|_| error("invalid HTTP request header"))?;
                request.headers
            };
            let mut length = None;
            for header in parsed_headers {
                if header.name.eq_ignore_ascii_case("transfer-encoding") {
                    self.stop();
                    return Err(error(
                        "file hashing requires Content-Length; transfer encoding is unsupported",
                    ));
                }
                if header.name.eq_ignore_ascii_case("content-length") {
                    let text = std::str::from_utf8(header.value)
                        .map_err(|_| error("invalid Content-Length"))?
                        .trim();
                    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(error("invalid Content-Length"));
                    }
                    let n: u64 = text.parse().map_err(|_| error("Content-Length overflow"))?;
                    if length.replace(n).is_some() {
                        return Err(error("duplicate Content-Length"));
                    }
                }
                if header.name.eq_ignore_ascii_case("content-type") {
                    self.mime = Some(
                        std::str::from_utf8(header.value)
                            .map_err(|_| error("invalid MIME metadata"))?
                            .to_owned(),
                    );
                }
            }
            let Some(length) = length else {
                self.stop();
                return Ok(None);
            };
            if length > 64 * 1024 * 1024 {
                self.stop();
                return Err(error("HTTP file exceeds 64 MiB hash limit"));
            }
            self.remaining = Some(length);
            self.size = length;
            self.header = Vec::new();
        }
        let remaining = self.remaining.as_mut().expect("header established length");
        let take = (*remaining).min(bytes.len() as u64) as usize;
        self.hash.update(&bytes[..take]);
        *remaining -= take as u64;
        if *remaining != 0 {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(Metadata {
            size: self.size,
            sha256: format!("{:x}", self.hash.clone().finalize()),
            mime: self.mime.take(),
        }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_body_is_hashed_without_retention() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n\r\nabc";
        for split in 0..input.len() {
            let mut file = HttpFile::default();
            file.allow_response(true);
            assert!(file.push(&input[..split]).unwrap().is_none());
            let result = file.push(&input[split..]).unwrap().unwrap();
            assert_eq!(
                result.sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            assert_eq!(result.size, 3);
            assert_eq!(result.mime.as_deref(), Some("text/plain"));
            assert_eq!(file.buffered_bytes(), 0);
            assert!(file.push(b"another response").unwrap().is_none());
        }
    }
    #[test]
    fn rejects_ambiguous_lengths_and_marks_truncation() {
        let mut file = HttpFile::default();
        file.allow_response(true);
        assert!(file
            .push(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc")
            .unwrap()
            .is_none());
        assert!(file.incomplete());
        for header in [
            "Content-Length: 1\r\nContent-Length: 2",
            "Transfer-Encoding: chunked",
            "Content-Length: -1",
            "Content-Length: 999999999",
        ] {
            assert!({
                let mut file = HttpFile::default();
                file.allow_response(true);
                file
            }
            .push(format!("HTTP/1.1 200 OK\r\n{header}\r\n\r\n").as_bytes())
            .is_err());
        }
        assert!(HttpFile::default()
            .push(b"SSH-2.0-test\r\n")
            .unwrap()
            .is_none());
    }
}
