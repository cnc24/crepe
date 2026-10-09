//! Bounded, passive TLS/HTTP/SSH handshake metadata. Never decrypts traffic.
use crepe_core::{Error, Result};
use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    FileMetadata {
        size: u64,
        sha256: String,
        mime: Option<String>,
    },
    TlsClientHello {
        legacy_version: u16,
        supported_versions: Vec<u16>,
        cipher_suites: Vec<u16>,
        server_name: Option<String>,
        alpn: Vec<String>,
        ech_present: bool,
    },
    TlsServerHello {
        legacy_version: u16,
        selected_version: Option<u16>,
        cipher_suite: u16,
    },
    HttpRequest {
        method: String,
        target: String,
        version: u8,
        host: Option<String>,
    },
    HttpResponse {
        status: u16,
        version: u8,
        server: Option<String>,
    },
    SshBanner {
        identification: String,
    },
}
impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::FileMetadata { .. } => "file.seen",
            Self::TlsClientHello { .. } => "tls.client_hello",
            Self::TlsServerHello { .. } => "tls.server_hello",
            Self::HttpRequest { .. } => "http.request",
            Self::HttpResponse { .. } => "http.response",
            Self::SshBanner { .. } => "ssh.banner",
        }
    }
}
#[derive(Debug)]
pub enum Inspection {
    More,
    Event(Event),
    Ignore,
}
fn error(code: &'static str, m: &str) -> Error {
    Error::new(code, m)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| error("CREPE-TLS-001", "TLS length overflow"))?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| error("CREPE-TLS-001", "truncated TLS field"))?;
        self.pos = end;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn v8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()?;
        self.take(n.into())
    }
    fn v16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()?;
        self.take(n.into())
    }
    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
}
fn text(b: &[u8], code: &'static str) -> Result<String> {
    if !b.iter().all(|c| matches!(c, 32..=126)) {
        return Err(error(code, "non-printable protocol metadata"));
    }
    Ok(String::from_utf8(b.to_vec()).unwrap())
}
fn words(b: &[u8]) -> Result<Vec<u16>> {
    if !b.len().is_multiple_of(2) {
        return Err(error("CREPE-TLS-001", "odd TLS u16 vector"));
    }
    Ok(b.as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect())
}
fn hello(kind: u8, bytes: &[u8]) -> Result<Event> {
    let mut c = Cursor { bytes, pos: 0 };
    let legacy_version = c.u16()?;
    c.take(32)?;
    let session = c.v8()?;
    if session.len() > 32 {
        return Err(error("CREPE-TLS-001", "TLS session ID too long"));
    }
    let mut cipher_suites = Vec::new();
    let mut cipher_suite = 0;
    if kind == 1 {
        cipher_suites = words(c.v16()?)?;
        if cipher_suites.is_empty() {
            return Err(error("CREPE-TLS-001", "empty cipher list"));
        }
        if c.v8()?.is_empty() {
            return Err(error("CREPE-TLS-001", "empty compression list"));
        }
    } else {
        cipher_suite = c.u16()?;
        c.u8()?;
    }
    let mut server_name = None;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();
    let mut selected_version = None;
    let mut ech_present = false;
    if !c.done() {
        let extension_bytes = c.v16()?;
        let mut ex = Cursor {
            bytes: extension_bytes,
            pos: 0,
        };
        let mut seen = std::collections::BTreeSet::new();
        while !ex.done() {
            let typ = ex.u16()?;
            let b = ex.v16()?;
            if !seen.insert(typ) {
                return Err(error("CREPE-TLS-001", "duplicate TLS extension"));
            }
            let mut e = Cursor { bytes: b, pos: 0 };
            match typ {
                0 if kind == 1 => {
                    let names = e.v16()?;
                    let mut names = Cursor {
                        bytes: names,
                        pos: 0,
                    };
                    while !names.done() {
                        let name_type = names.u8()?;
                        let value = names.v16()?;
                        if name_type == 0 {
                            if server_name.is_some() || value.is_empty() {
                                return Err(error("CREPE-TLS-001", "invalid duplicate/empty SNI"));
                            }
                            server_name = Some(text(value, "CREPE-TLS-001")?);
                        }
                    }
                }
                16 if kind == 1 => {
                    let values = e.v16()?;
                    let mut values = Cursor {
                        bytes: values,
                        pos: 0,
                    };
                    while !values.done() {
                        let value = values.v8()?;
                        if value.is_empty() {
                            return Err(error("CREPE-TLS-001", "empty ALPN"));
                        }
                        alpn.push(text(value, "CREPE-TLS-001")?);
                    }
                }
                43 if kind == 1 => supported_versions = words(e.v8()?)?,
                43 => selected_version = Some(e.u16()?),
                0xfe0d => {
                    ech_present = true;
                    e.take(b.len())?;
                }
                _ => {
                    e.take(b.len())?;
                }
            }
            if !e.done() {
                return Err(error("CREPE-TLS-001", "trailing TLS extension bytes"));
            }
        }
    }
    if !c.done() {
        return Err(error("CREPE-TLS-001", "trailing TLS Hello bytes"));
    }
    Ok(if kind == 1 {
        Event::TlsClientHello {
            legacy_version,
            supported_versions,
            cipher_suites,
            server_name,
            alpn,
            ech_present,
        }
    } else {
        Event::TlsServerHello {
            legacy_version,
            selected_version,
            cipher_suite,
        }
    })
}
fn tls(bytes: &[u8]) -> Result<Inspection> {
    let mut pos = 0;
    let mut handshake = Vec::new();
    while pos + 5 <= bytes.len() {
        let h = &bytes[pos..pos + 5];
        if h[0] != 22 {
            return Ok(Inspection::Ignore);
        }
        if h[1] != 3 {
            return Err(error("CREPE-TLS-001", "invalid TLS record version"));
        }
        let n = usize::from(u16::from_be_bytes([h[3], h[4]]));
        if n == 0 || n > 18432 {
            return Err(error("CREPE-TLS-001", "TLS record size limit"));
        }
        if bytes.len() - pos < 5 + n {
            return Ok(Inspection::More);
        }
        handshake.extend_from_slice(&bytes[pos + 5..pos + 5 + n]);
        pos += 5 + n;
        if handshake.len() > 65536 {
            return Err(error("CREPE-TLS-001", "TLS handshake size limit"));
        }
        if handshake.len() >= 4 {
            if !matches!(handshake[0], 1 | 2) {
                return Ok(Inspection::Ignore);
            }
            let len = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if len > 65532 {
                return Err(error("CREPE-TLS-001", "TLS Hello size limit"));
            }
            if handshake.len() >= 4 + len {
                return Ok(Inspection::Event(hello(
                    handshake[0],
                    &handshake[4..4 + len],
                )?));
            }
        }
    }
    Ok(Inspection::More)
}
#[derive(Debug, Clone, Copy)]
pub struct Enabled {
    pub tls: bool,
    pub http: bool,
    pub ssh: bool,
}
impl Default for Enabled {
    fn default() -> Self {
        Self {
            tls: true,
            http: true,
            ssh: true,
        }
    }
}
pub fn inspect(bytes: &[u8]) -> Result<Inspection> {
    inspect_enabled(bytes, Enabled::default())
}
pub fn inspect_enabled(bytes: &[u8], enabled: Enabled) -> Result<Inspection> {
    if bytes.len() > 65536 {
        return Err(error("CREPE-L7-001", "protocol header limit"));
    }
    if bytes.is_empty() {
        return Ok(Inspection::More);
    }
    if bytes[0] == 22 {
        if !enabled.tls {
            return Ok(Inspection::Ignore);
        }
        return tls(bytes);
    }
    if bytes.starts_with(b"SSH-") || bytes.windows(5).any(|p| p == b"\nSSH-") {
        if !enabled.ssh {
            return Ok(Inspection::Ignore);
        }
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            if line.starts_with(b"SSH-") {
                if !line.ends_with(b"\n") {
                    return Ok(Inspection::More);
                }
                if line.len() > 255 {
                    return Err(error("CREPE-SSH-001", "SSH banner exceeds 255 bytes"));
                }
                let banner = text(
                    line.strip_suffix(b"\n")
                        .unwrap()
                        .strip_suffix(b"\r")
                        .unwrap_or(line.strip_suffix(b"\n").unwrap()),
                    "CREPE-SSH-001",
                )?;
                if !banner.starts_with("SSH-2.0-") && !banner.starts_with("SSH-1.99-") {
                    return Err(error("CREPE-SSH-001", "unsupported SSH protocol version"));
                }
                return Ok(Inspection::Event(Event::SshBanner {
                    identification: banner,
                }));
            }
        }
    }
    let http = bytes.starts_with(b"HTTP/")
        || [
            b"GET ".as_slice(),
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"TRACE ",
        ]
        .iter()
        .any(|p| bytes.starts_with(p));
    if http {
        if !enabled.http {
            return Ok(Inspection::Ignore);
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        if bytes.starts_with(b"HTTP/") {
            let mut response = httparse::Response::new(&mut headers);
            match response
                .parse(bytes)
                .map_err(|e| Error::new("CREPE-HTTP-001", e))?
            {
                httparse::Status::Partial => return Ok(Inspection::More),
                httparse::Status::Complete(_) => {
                    let server = response
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("server"))
                        .map(|h| text(h.value, "CREPE-HTTP-001"))
                        .transpose()?;
                    return Ok(Inspection::Event(Event::HttpResponse {
                        status: response.code.unwrap(),
                        version: response.version.unwrap(),
                        server,
                    }));
                }
            }
        } else {
            let mut request = httparse::Request::new(&mut headers);
            match request
                .parse(bytes)
                .map_err(|e| Error::new("CREPE-HTTP-001", e))?
            {
                httparse::Status::Partial => return Ok(Inspection::More),
                httparse::Status::Complete(_) => {
                    let host = request
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("host"))
                        .map(|h| text(h.value, "CREPE-HTTP-001"))
                        .transpose()?;
                    return Ok(Inspection::Event(Event::HttpRequest {
                        method: request.method.unwrap().into(),
                        target: request.path.unwrap().into(),
                        version: request.version.unwrap(),
                        host,
                    }));
                }
            }
        }
    }
    if bytes.len() >= 8192 {
        Ok(Inspection::Ignore)
    } else {
        Ok(Inspection::More)
    }
}
