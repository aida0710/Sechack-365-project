use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};
use crate::app::{App, CurrentScreen};

pub fn draw(f: &mut Frame, app: &App) {
    match app.current_screen {
        CurrentScreen::Main => draw_main_screen(f, app),
        CurrentScreen::SelectNetwork => draw_select_network_screen(f, app),
        CurrentScreen::Exiting => {}
    }
}

fn draw_main_screen(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ]
                .as_ref(),
        )
        .split(f.size());

    let title = Paragraph::new("Packet Capture")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let header_cells = ["No.", "Source IP:Port", "Destination IP:Port", "Protocol"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::Blue))
        .height(1)
        .bottom_margin(1);

    let rows = app.captured_packets.iter().map(|(i, packet)| {
        let (src_ip, src_port, dst_ip, dst_port, protocol) = parse_packet_info(packet);
        Row::new(vec![
            Cell::from(i.to_string()),
            Cell::from(format!("{}:{}", src_ip, src_port)),
            Cell::from(format!("{}:{}", dst_ip, dst_port)),
            Cell::from(protocol),
        ]).height(1)
    });

    let widths = [
        Constraint::Percentage(10),
        Constraint::Percentage(35),
        Constraint::Percentage(35),
        Constraint::Percentage(20),
    ];

    let table = Table::new(rows, &widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Captured Packets"));

    let mut state = TableState::default();
    state.select(Some(app.captured_packets.len().saturating_sub(1))); // 自動スクロール

    f.render_stateful_widget(table, chunks[1], &mut state);

    let current_device = app.selected_device.as_ref().map_or("None", |d| d.name.as_str());
    let capture_status = if app.is_capturing { "Running" } else { "Stopped" };
    let mut footer_content = vec![
        Span::raw("c: キャプチャ開始/停止 | s: ネットワークデバイス選択 | r: リセット | q: 終了 "),
    ];

    if let Some(message) = &app.message {
        footer_content.push(Span::raw(" | "));
        footer_content.push(Span::styled(message, Style::default().fg(Color::Yellow)));
    }

    let footer = Paragraph::new(Line::from(footer_content))
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title(format!("Selected Device: {} | Capture: {}", current_device, capture_status)));
    f.render_widget(footer, chunks[2]);
}

fn draw_select_network_screen(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ]
                .as_ref(),
        )
        .split(f.size());

    let title = Paragraph::new("ネットワークデバイスを選択してください")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let devices: Vec<Row> = app.available_devices
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let style = if i == app.selected_device_index {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![Cell::from(d.name.clone())]).style(style)
        })
        .collect();

    let devices_table = Table::new(devices, &[Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title("Available Devices"));
    f.render_widget(devices_table, chunks[1]);

    let mut footer_content = vec![
        Span::raw("↑↓: 選択切り替え | Enter: 選択 | Esc: キャンセル"),
    ];

    if let Some(message) = &app.message {
        footer_content.push(Span::raw(" | "));
        footer_content.push(Span::styled(message, Style::default().fg(Color::Yellow)));
    }

    let footer = Paragraph::new(Line::from(footer_content))
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn parse_packet_info(packet: &str) -> (String, String, String, String, String) {
    let parts: Vec<&str> = packet.split(" > ").collect();
    if parts.len() < 2 {
        return ("Unknown".to_string(), "0".to_string(), "Unknown".to_string(), "0".to_string(), "Unknown".to_string());
    }

    let src_parts: Vec<&str> = parts[0].split(':').collect();
    let dst_parts: Vec<&str> = parts[1].split_whitespace().next().unwrap_or("").split(':').collect();
    let protocol = parts[1].split_whitespace().last().unwrap_or("Unknown");

    (
        src_parts.get(0).unwrap_or(&"Unknown").to_string(),
        src_parts.get(1).unwrap_or(&"0").to_string(),
        dst_parts.get(0).unwrap_or(&"Unknown").to_string(),
        dst_parts.get(1).unwrap_or(&"0").to_string(),
        protocol.to_string(),
    )
}