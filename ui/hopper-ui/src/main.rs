use hopper_core::TunnelState;
use iced::widget::{button, column, container, row, text};
use iced::{Element, Fill, Task, Theme};

#[derive(Debug, Clone)]
enum Message {
    Connect,
    Disconnect,
}

#[derive(Default)]
struct HopperApp {
    tunnel_state: TunnelState,
}

fn update(app: &mut HopperApp, message: Message) -> Task<Message> {
    match message {
        Message::Connect => app.tunnel_state = TunnelState::Connecting,
        Message::Disconnect => app.tunnel_state = TunnelState::Disconnected,
    }

    Task::none()
}

fn view(app: &HopperApp) -> Element<'_, Message> {
    let status = match app.tunnel_state {
        TunnelState::Disconnected => "Disconnected",
        TunnelState::Connecting => "Connecting…",
        TunnelState::Connected => "Connected",
        TunnelState::Disconnecting => "Disconnecting…",
        TunnelState::Failed => "Connection failed",
    };

    let controls = row![
        button("Connect").on_press(Message::Connect),
        button("Disconnect").on_press(Message::Disconnect),
    ]
    .spacing(12);

    let content = column![
        text("Hopper Desktop").size(32),
        text("Windows first · macOS/Linux ready architecture"),
        text(format!("Status: {status}")),
        controls,
    ]
    .spacing(18)
    .padding(24);

    container(content).center_x(Fill).center_y(Fill).into()
}

fn main() -> iced::Result {
    iced::application(HopperApp::default, update, view)
        .title("Hopper Desktop")
        .theme(Theme::Dark)
        .centered()
        .run()
}
