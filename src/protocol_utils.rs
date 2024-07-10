use std::collections::HashMap;

// ポート番号からプロトコル名へのマッピングを作成する関数
fn create_port_protocol_map() -> HashMap<u16, &'static str> {
    let mut map = HashMap::new();
    map.insert(20, "FTP-DATA");
    map.insert(21, "FTP");
    map.insert(22, "SSH");
    map.insert(23, "Telnet");
    map.insert(25, "SMTP");
    map.insert(43, "WHOIS");
    map.insert(53, "DNS");
    map.insert(67, "DHCP");
    map.insert(68, "DHCP");
    map.insert(69, "TFTP");
    map.insert(80, "HTTP");
    map.insert(88, "Kerberos");
    map.insert(110, "POP3");
    map.insert(123, "NTP");
    map.insert(137, "NetBIOS Name Service");
    map.insert(138, "NetBIOS Datagram Service");
    map.insert(139, "NetBIOS Session Service");
    map.insert(143, "IMAP");
    map.insert(161, "SNMP");
    map.insert(162, "SNMP Trap");
    map.insert(179, "BGP");
    map.insert(194, "IRC");
    map.insert(389, "LDAP");
    map.insert(427, "SLP");
    map.insert(443, "HTTPS");
    map.insert(445, "Microsoft-DS (SMB)");
    map.insert(465, "SMTPS");
    map.insert(514, "Syslog");
    map.insert(548, "AFP");
    map.insert(587, "SMTP (submission)");
    map.insert(631, "IPP");
    map.insert(636, "LDAPS");
    map.insert(873, "rsync");
    map.insert(989, "FTPS (data)");
    map.insert(990, "FTPS (control)");
    map.insert(993, "IMAPS");
    map.insert(995, "POP3S");
    map.insert(1080, "SOCKS Proxy");
    map.insert(1194, "OpenVPN");
    map.insert(1433, "Microsoft SQL Server");
    map.insert(1521, "Oracle");
    map.insert(1723, "PPTP");
    map.insert(1812, "RADIUS");
    map.insert(2049, "NFS");
    map.insert(2222, "SSH");
    map.insert(3306, "MySQL");
    map.insert(3389, "RDP");
    map.insert(3690, "SVN");
    map.insert(4369, "Erlang Port Mapper Daemon");
    map.insert(5060, "SIP");
    map.insert(5061, "SIP (TLS)");
    map.insert(5222, "XMPP");
    map.insert(5353, "mDNS");
    map.insert(5432, "PostgreSQL");
    map.insert(5671, "AMQP (TLS)");
    map.insert(5672, "AMQP");
    map.insert(5900, "VNC");
    map.insert(6379, "Redis");
    map.insert(6667, "IRC");
    map.insert(8000, "Alternative HTTP");
    map.insert(8080, "HTTP");
    map.insert(8086, "InfluxDB");
    map.insert(8443, "HTTPS");
    map.insert(9000, "Prometheus");
    map.insert(9092, "Kafka");
    map.insert(9200, "Elasticsearch");
    map.insert(9418, "Git");
    map.insert(11211, "Memcached");
    map.insert(19132, "Minecraft");
    map.insert(19133, "Minecraft");
    map.insert(25565, "Minecraft");
    map.insert(27017, "MongoDB");
    map
}

// ポート番号からプロトコルを推定する関数
pub fn guess_protocol(port: u16) -> String {
    let port_map = create_port_protocol_map();
    port_map.get(&port)
        .map(|&protocol| format!("{}(推定)", protocol))
        .unwrap_or_else(|| "Unknown".to_string())
}