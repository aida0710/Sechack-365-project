#[derive(Debug, PartialEq)]
pub enum ApplicationProtocol {
    HTTP,
    HTTPS,
    FTP,
    SSH,
    Telnet,
    SMTP,
    POP3,
    IMAP,
    DNS,
    MySQL,
    PostgreSQL,
    MongoDB,
    Redis,
    MSSQLServer,
    AMQP,
    Elasticsearch,
    SNMP,
    LDAP,
    Unknown,
}

pub fn identify_protocol(src_port: u16, dst_port: u16, payload: &[u8]) -> ApplicationProtocol {
    match (src_port, dst_port) {
        (80, _) | (_, 80) | (8080, _) | (_, 8080) => ApplicationProtocol::HTTP,
        (443, _) | (_, 443) | (8443, _) | (_, 8443) => ApplicationProtocol::HTTPS,
        (21, _) | (_, 21) => ApplicationProtocol::FTP,
        (22, _) | (_, 22) => ApplicationProtocol::SSH,
        (23, _) | (_, 23) => ApplicationProtocol::Telnet,
        (25, _) | (_, 25) => ApplicationProtocol::SMTP,
        (110, _) | (_, 110) => ApplicationProtocol::POP3,
        (143, _) | (_, 143) => ApplicationProtocol::IMAP,
        (53, _) | (_, 53) => ApplicationProtocol::DNS,
        (3306, _) | (_, 3306) => ApplicationProtocol::MySQL,
        (5432, _) | (_, 5432) => ApplicationProtocol::PostgreSQL,
        (27017, _) | (_, 27017) => ApplicationProtocol::MongoDB,
        (6379, _) | (_, 6379) => ApplicationProtocol::Redis,
        (1433, _) | (_, 1433) => ApplicationProtocol::MSSQLServer,
        (5672, _) | (_, 5672) => ApplicationProtocol::AMQP,
        (9200, _) | (_, 9200) => ApplicationProtocol::Elasticsearch,
        (161, _) | (_, 161) => ApplicationProtocol::SNMP,
        (389, _) | (_, 389) => ApplicationProtocol::LDAP,
        _ => {
            // ペイロードの内容に基づいて識別を試みる
            if payload.starts_with(b"HTTP/") || payload.starts_with(b"GET ") || payload.starts_with(b"POST ") {
                ApplicationProtocol::HTTP
            } else if payload.starts_with(b"SSH-") {
                ApplicationProtocol::SSH
            } else if payload.starts_with(b"220") && payload.windows(3).any(|window| window == b"FTP") {
                ApplicationProtocol::FTP
            } else if payload.starts_with(b"EHLO") || payload.starts_with(b"HELO") {
                ApplicationProtocol::SMTP
            } else if payload.starts_with(b"+OK") {
                ApplicationProtocol::POP3
            } else if payload.starts_with(b"* OK") {
                ApplicationProtocol::IMAP
            } else {
                ApplicationProtocol::Unknown
            }
        }
    }
}