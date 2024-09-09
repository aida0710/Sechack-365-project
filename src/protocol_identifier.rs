#[derive(Debug, PartialEq)]
pub enum ApplicationProtocol {
    HTTP,
    HTTPS,
    FTP,
    SSH,
    SMTP,
    DNS,
    Unknown,
}

pub fn identify_protocol(src_port: u16, dst_port: u16, payload: &[u8]) -> ApplicationProtocol {
    match (src_port, dst_port) {
        (80, _) | (_, 80) => ApplicationProtocol::HTTP,
        (443, _) | (_, 443) => ApplicationProtocol::HTTPS,
        (21, _) | (_, 21) => ApplicationProtocol::FTP,
        (22, _) | (_, 22) => ApplicationProtocol::SSH,
        (25, _) | (_, 25) => ApplicationProtocol::SMTP,
        (53, _) | (_, 53) => ApplicationProtocol::DNS,
        _ => {
            // ペイロードの内容に基づいて識別を試みる
            if payload.starts_with(b"HTTP/") || payload.starts_with(b"GET ") || payload.starts_with(b"POST ") {
                ApplicationProtocol::HTTP
            } else {
                ApplicationProtocol::Unknown
            }
        }
    }
}