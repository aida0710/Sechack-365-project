use std::collections::VecDeque;
use pcap::Device;
use crate::network;

pub enum CurrentScreen {
    Main,
    SelectNetwork,
    Exiting,
}

pub struct App {
    pub current_screen: CurrentScreen,
    pub selected_device: Option<Device>,
    pub captured_packets: VecDeque<(usize, String)>,
    pub is_capturing: bool,
    pub available_devices: Vec<Device>,
    pub selected_device_index: usize,
    pub packet_count: usize,
    pub message: Option<String>,
    pub device_changed: bool,
    pub exit_selected_button: usize, // 0: Yes, 1: No
}

impl App {
    pub fn new() -> Self {
        Self {
            current_screen: CurrentScreen::Main,
            selected_device: None,
            captured_packets: VecDeque::with_capacity(1000),
            is_capturing: false,
            available_devices: Vec::new(),
            selected_device_index: 0,
            packet_count: 0,
            message: None,
            device_changed: false,
            exit_selected_button: 0,
        }
    }

    pub fn toggle_capture(&mut self) -> bool {
        if self.selected_device.is_some() {
            self.message = None;
            self.is_capturing = !self.is_capturing;
            true
        } else {
            self.set_message("ネットワークデバイスを選択してからCaptureを開始してください。");
            false
        }
    }

    pub fn add_captured_packet(&mut self, packet_info: String) {
        if self.captured_packets.len() >= 1000 {
            self.captured_packets.pop_front();
        }
        self.packet_count += 1;
        self.captured_packets.push_back((self.packet_count, packet_info));
    }

    pub fn next_device(&mut self) {
        if !self.available_devices.is_empty() {
            self.selected_device_index = (self.selected_device_index + 1) % self.available_devices.len();
        }
    }

    pub fn previous_device(&mut self) {
        if !self.available_devices.is_empty() {
            self.selected_device_index = self.selected_device_index.checked_sub(1)
                .unwrap_or(self.available_devices.len() - 1);
        }
    }

    pub fn select_current_device(&mut self) {
        if let Some(new_device) = self.available_devices.get(self.selected_device_index).cloned() {
            if self.selected_device.as_ref().map(|d| d.name != new_device.name).unwrap_or(true) {
                self.selected_device = Some(new_device);
                self.set_message(&format!("デバイス {} を選択しました", self.selected_device.as_ref().unwrap().name));

                if self.is_capturing {
                    self.is_capturing = false;
                }

                self.device_changed = true;
            }
        }
    }

    pub fn reset(&mut self) {
        self.current_screen = CurrentScreen::Main;
        self.selected_device = None;
        self.captured_packets.clear();
        self.is_capturing = false;
        self.selected_device_index = 0;
        self.packet_count = 0;
        self.message = None;

        match network::get_available_devices() {
            Ok(devices) => self.available_devices = devices,
            Err(_) => {
                self.available_devices.clear();
                self.set_message("ネットワークデバイスのスキャンに失敗しました。");
            }
        }
    }

    pub fn set_message(&mut self, message: &str) {
        self.message = Some(message.to_string());
    }
}