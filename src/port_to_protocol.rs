use std::collections::HashMap;

// ポート番号からプロトコル名へのマッピングを作成する関数
fn create_port_protocol_map() -> HashMap<u16, &'static str> {
    let mut map = HashMap::new();
    map.insert(22, "SSH");
    map.insert(80, "HTTP");
    map.insert(443, "HTTPS");
    map.insert(21, "FTP");
    map.insert(25, "SMTP");
    map.insert(53, "DNS");
    map.insert(110, "POP3");
    map.insert(143, "IMAP");
    map.insert(3306, "MySQL");
    map.insert(5432, "PostgreSQL");
    map.insert(2222, "SSH");
    map.insert(8080, "HTTP");
    map.insert(8443, "HTTPS");
    map.insert(19132, "Minecraft");
    map
}

// ポート番号からプロトコルを推定する関数
#[allow(dead_code)]
pub fn guess_protocol(port: u16) -> String {
    let port_map = create_port_protocol_map();
    port_map.get(&port)
        .map(|&protocol| format!("{}(推定)", protocol))
        .unwrap_or_else(|| "Unknown".to_string())
}