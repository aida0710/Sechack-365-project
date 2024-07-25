mod app;
mod ui;
mod network;
mod packet;
mod error;
mod protocol_utils;

use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crate::app::{App, CurrentScreen};
use crate::network::get_available_devices;
use crate::packet::start_packet_capture;
use crate::error::Result;

fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let app = Arc::new(Mutex::new(App::new()));
    {
        let mut app_lock = app.lock().unwrap();
        app_lock.available_devices = get_available_devices()?;
    }

    let app_clone = Arc::clone(&app);
    std::thread::spawn(move || {
        if let Err(e) = start_packet_capture(app_clone) {
            eprintln!("Packet capture error: {}", e);
        }
    });

    // Main event loop
    loop {
        {
            let app_lock = app.lock().unwrap();
            terminal.draw(|f| ui::draw(f, &app_lock))?;
        }
        if event::poll(std::time::Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                let mut app_lock = app.lock().unwrap();
                match app_lock.current_screen {
                    CurrentScreen::Main => handle_main_screen_input(&mut app_lock, key),
                    CurrentScreen::SelectNetwork => handle_select_network_input(&mut app_lock, key),
                    CurrentScreen::Exiting => {
                        if handle_exit_screen_input(&mut app_lock, key) {
                            break; // アプリケーションを終了
                        }
                    },
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn handle_main_screen_input(app: &mut App, key: event::KeyEvent) {
    match key.code {
        KeyCode::Char('q') => {
            app.current_screen = CurrentScreen::Exiting;
            app.exit_selected_button = 0; // デフォルトで"はい"を選択
        },
        KeyCode::Char('s') => app.current_screen = CurrentScreen::SelectNetwork,
        KeyCode::Char('c') => { app.toggle_capture(); },
        KeyCode::Char('r') => app.reset(),
        _ => {}
    }
}

fn handle_select_network_input(app: &mut App, key: event::KeyEvent) {
    match key.code {
        KeyCode::Up => app.previous_device(),
        KeyCode::Down => app.next_device(),
        KeyCode::Enter => {
            app.select_current_device();
            app.current_screen = CurrentScreen::Main;
        }
        KeyCode::Esc => app.current_screen = CurrentScreen::Main,
        _ => {}
    }
}

fn handle_exit_screen_input(app: &mut App, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Left | KeyCode::Right => {
            app.exit_selected_button = 1 - app.exit_selected_button; // 0と1を切り替え
        }
        KeyCode::Enter => {
            if app.exit_selected_button == 0 {
                return true; // "はい"が選択された場合、終了
            } else {
                app.current_screen = CurrentScreen::Main;
            }
        }
        KeyCode::Esc => {
            app.current_screen = CurrentScreen::Main;
        }
        _ => {}
    }
    false
}
