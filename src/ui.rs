use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};
use ratatui::layout::Rect;
use crate::app::{App, CurrentScreen};
use crate::protocol_utils::guess_protocol;

pub fn draw(frame: &mut Frame, app: &App) {
    match app.current_screen {
        CurrentScreen::Main => draw_main_screen(frame, app),
        CurrentScreen::SelectNetwork => draw_select_network_screen(frame, app),
        CurrentScreen::Exiting => draw_exit_screen(frame, app),
    }
}

fn draw_main_screen(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(vec![
            Constraint::Length(3), // Title
            Constraint::Min(0), // Packets
            Constraint::Length(3), // Footer
        ])
        .split(frame.size());

    let title = Paragraph::new("Packet Capture")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let header_cells = [
        "Count",
        "Source IP",
        "Port:Inferred Protocol",
        "Stream",
        "Destination IP",
        "Port:Inferred Protocol",
        "Protocol"
    ].iter().map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));

    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::Blue))
        .height(1)
        .bottom_margin(1);

    let rows = app.captured_packets.iter().map(|(index, packet)| {
        let (src_ip, src_port, dst_ip, dst_port, protocol) = parse_packet_info(packet);
        Row::new(vec![
            Cell::from(index.to_string()),
            Cell::from(format!("{}", src_ip)),
            Cell::from(format!("{:>6}:{}", src_port, guess_protocol(src_port.parse::<u16>().unwrap_or(0)))), // Guess protocol
            Cell::from("->"),
            Cell::from(format!("{}", dst_ip)),
            Cell::from(format!("{:>6}:{}", dst_port, guess_protocol(dst_port.parse::<u16>().unwrap_or(0)))), // Guess protocol
            Cell::from(protocol),
        ]).height(1)
    });

    let table = Table::new(rows, &[
        Constraint::Percentage(10), // Count.
        Constraint::Percentage(12), // Source IP
        Constraint::Percentage(16), // Port
        Constraint::Percentage(8), // Stream
        Constraint::Percentage(12), // Destination IP
        Constraint::Percentage(16), // Port
        Constraint::Percentage(8), // Protocol
    ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Captured Packets"));

    let mut state = TableState::default();
    state.select(Some(app.captured_packets.len().saturating_sub(1))); // Auto-scroll
    frame.render_stateful_widget(table, chunks[1], &mut state);

    let footer = create_footer(app);
    frame.render_widget(footer, chunks[2]);
}

fn draw_select_network_screen(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(vec![
            Constraint::Length(3), // Title
            Constraint::Min(0), // Devices
            Constraint::Length(3), // Footer
        ])
        .split(frame.size());

    let title = Paragraph::new("ネットワークデバイスを選択してください")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let devices: Vec<Row> = app.available_devices
        .iter()
        .enumerate()
        .map(|(index, device)| {
            let style = if index == app.selected_device_index {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![Cell::from(device.name.clone())]).style(style)
        })
        .collect();

    let devices_table = Table::new(devices, &[Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title("Available Devices"));
    frame.render_widget(devices_table, chunks[1]);

    let footer = create_footer(app);
    frame.render_widget(footer, chunks[2]);
}

fn create_footer(app: &App) -> Paragraph {
    let mut footer_content = vec![
        Span::raw("c: キャプチャ開始/停止 | s: ネットワークデバイス選択 | r: リセット | q: 終了 "),
    ];

    if let Some(message) = &app.message {
        footer_content.push(Span::raw(" | "));
        footer_content.push(Span::styled(message, Style::default().fg(Color::Yellow)));
    }

    let current_device = app.selected_device.as_ref().map_or("None", |d| d.name.as_str());
    let capture_status = if app.is_capturing { "Running" } else { "Stopped" };

    Paragraph::new(Line::from(footer_content))
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title(format!("Selected Device: {} | Capture: {}", current_device, capture_status)))
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

fn draw_exit_screen(frame: &mut Frame, app: &App) {
    let size = frame.size();

    let area = centered_rect(60, 20, size);

    let block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default());
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(vec![
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);

    let title = Paragraph::new("終了確認")
        .style(Style::default())
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(title, chunks[0]);

    let text = Paragraph::new("本当に終了しますか？")
        .style(Style::default())
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(text, chunks[1]);

    let buttons_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);

    let yes_style = if app.exit_selected_button == 0 {
        Style::default().fg(Color::Black).bg(Color::White)
    } else {
        Style::default().fg(Color::White)
    };
    let no_style = if app.exit_selected_button == 1 {
        Style::default().fg(Color::Black).bg(Color::White)
    } else {
        Style::default().fg(Color::White)
    };

    let yes_button = Paragraph::new(Line::from(vec![
        Span::styled("はい", yes_style),
    ])).alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(yes_button, buttons_layout[0]);

    let no_button = Paragraph::new(Line::from(vec![
        Span::styled("いいえ", no_style),
    ])).alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(no_button, buttons_layout[1]);
}

// 中央に配置するための関数
fn centered_rect(percent_x: u16, percent_y: u16, rect: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(rect);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}