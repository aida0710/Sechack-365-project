use std::net::Ipv4Addr;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SettingsPattern {
    Default,
    Fast,
    Large,
    Attack,
}

#[derive(Clone)]
pub struct SendPacketSettings {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_size: usize,
    pub timeout: Duration,
    pub payload: Vec<u8>,
    pub packet_count: usize,
    pub interval: Duration,
}

impl SendPacketSettings {
    fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        packet_size: usize,
        timeout: Duration,
        payload: Vec<u8>,
        packet_count: usize,
        interval: Duration,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            packet_size,
            timeout,
            payload,
            packet_count,
            interval,
        }
    }
}

pub struct SettingsLocator {
    patterns: HashMap<SettingsPattern, Arc<SendPacketSettings>>,
}

impl SettingsLocator {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();

        patterns.insert(
            SettingsPattern::Default,
            Arc::new(SendPacketSettings::new(
                "1.1.1.1".parse().unwrap(),
                "192.168.1.80".parse().unwrap(),
                50000,
                50000,
                1000,
                Duration::from_secs(10),
                vec![0; 1000],
                1000,
                Duration::from_millis(1000),
            )),
        );

        patterns.insert(
            SettingsPattern::Fast,
            Arc::new(SendPacketSettings::new(
                "1.1.1.1".parse().unwrap(),
                "192.168.1.80".parse().unwrap(),
                50000,
                50000,
                500,
                Duration::from_secs(5),
                vec![0; 500],
                5000,
                Duration::from_millis(100),
            )),
        );

        patterns.insert(
            SettingsPattern::Large,
            Arc::new(SendPacketSettings::new(
                "1.1.1.1".parse().unwrap(),
                "192.168.1.80".parse().unwrap(),
                50000,
                50000,
                8000,
                Duration::from_secs(30),
                vec![0; 8000],
                100,
                Duration::from_secs(1),
            )),
        );

        patterns.insert(
            SettingsPattern::Attack,
            Arc::new(SendPacketSettings::new(
                "192.168.0.13".parse().unwrap(),
                "192.168.0.150".parse().unwrap(),
                50000,
                50000,
                8000,
                Duration::from_millis(30),
                vec![0; 1000],
                100000000000000,
                Duration::from_nanos(30),
            )),
        );

        Self { patterns }
    }

    pub fn get_settings(&self, pattern: &SettingsPattern) -> Option<Arc<SendPacketSettings>> {
        self.patterns.get(pattern).cloned()
    }
}