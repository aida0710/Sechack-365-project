mod send_notice_packet;
mod app;
mod select_network;
mod packet_capture;
mod packet_parser;
mod port_to_protocol;
mod ui;

use app::{App, CurrentScreen};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        app_lock.available_devices = select_network::get_available_devices()?;
    }

    let app_clone = Arc::clone(&app);
    std::thread::spawn(move || {
        packet_capture::start_packet_capture(app_clone).unwrap();
    });

    // Main loop
    loop {
        {
            let app_lock = app.lock().unwrap();
            terminal.draw(|f| ui::draw(f, &app_lock))?;
        }

        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                let mut app_lock = app.lock().unwrap();
                match app_lock.current_screen {
                    CurrentScreen::Main => {
                        match key.code {
                            KeyCode::Char('q') => {
                                app_lock.current_screen = CurrentScreen::Exiting;
                            }
                            KeyCode::Char('s') => {
                                app_lock.current_screen = CurrentScreen::SelectNetwork;
                            }
                            KeyCode::Char('c') => {
                                app_lock.toggle_capture();
                            },
                            KeyCode::Char('r') => {
                                app_lock.reset();
                                // キャプチャスレッドを再起動
                                let app_clone = Arc::clone(&app);
                                std::thread::spawn(move || {
                                    packet_capture::start_packet_capture(app_clone).unwrap();
                                });
                            },
                            _ => {}
                        }
                    }
                    CurrentScreen::SelectNetwork => {
                        match key.code {
                            KeyCode::Up => app_lock.previous_device(),
                            KeyCode::Down => app_lock.next_device(),
                            KeyCode::Enter => {
                                app_lock.select_current_device();
                                app_lock.current_screen = CurrentScreen::Main;
                                if app_lock.device_changed {
                                    let app_clone = Arc::clone(&app);
                                    std::thread::spawn(move || {
                                        packet_capture::start_packet_capture(app_clone).unwrap();
                                    });
                                }
                            }
                            KeyCode::Esc => {
                                app_lock.current_screen = CurrentScreen::Main;
                            }
                            _ => {}
                        }
                    }
                    CurrentScreen::Exiting => {
                        break;
                    }
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