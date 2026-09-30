use hopper_core::{
    MAX_HOST_CHARS, MAX_PASSWORD_CHARS, MAX_SERVER_NAME_CHARS, MAX_SSH_USER_CHARS,
    ManualServerConnection, TunnelState,
};
use iced::widget::{Space, button, column, container, row, text, text_input};
use iced::{Element, Fill, Length, Task, Theme};

/// Какой экран сейчас открыт.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Servers,
    AddServer,
}

/// Все события UI.
///
/// Iced работает примерно по модели:
///
/// UI -> Message -> update() -> новое состояние -> view()
#[derive(Debug, Clone)]
enum Message {
    // Навигация.
    OpenHome,
    OpenServers,
    OpenAddServer,

    // Поля формы.
    ServerNameChanged(String),
    ServerHostChanged(String),
    ServerPortChanged(String),
    ServerUserChanged(String),
    ServerPasswordChanged(String),

    // Действия формы.
    ValidateServer,
    CancelAddServer,

    // VPN-заглушки.
    Connect,
    Disconnect,
}

/// Состояние формы добавления сервера.
///
/// Пока оно существует только в UI.
/// Ничего из этого автоматически на диск не записывается.
#[derive(Debug, Clone)]
struct AddServerForm {
    name: String,
    host: String,
    port: String,
    user: String,
    password: String,

    /// Сообщение под формой:
    /// ошибка или результат проверки.
    status: Option<String>,
}

impl Default for AddServerForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: String::new(),

            // Hopper по умолчанию использует SSH port 22.
            port: "22".to_string(),

            // Большинство Hopper VPS сейчас используются под root.
            user: "root".to_string(),

            password: String::new(),
            status: None,
        }
    }
}

/// Главное состояние desktop-приложения.
struct HopperApp {
    screen: Screen,
    tunnel_state: TunnelState,
    add_server: AddServerForm,
}

impl Default for HopperApp {
    fn default() -> Self {
        Self {
            screen: Screen::Home,
            tunnel_state: TunnelState::Disconnected,
            add_server: AddServerForm::default(),
        }
    }
}

/// Обработка всех событий приложения.
fn update(app: &mut HopperApp, message: Message) -> Task<Message> {
    match message {
        Message::OpenHome => {
            app.screen = Screen::Home;
        }

        Message::OpenServers => {
            app.screen = Screen::Servers;
        }

        Message::OpenAddServer => {
            // Каждый раз при открытии формы начинаем
            // с чистого состояния.
            app.add_server = AddServerForm::default();
            app.screen = Screen::AddServer;
        }

        Message::CancelAddServer => {
            // Пароль исчезает вместе с формой.
            app.add_server = AddServerForm::default();
            app.screen = Screen::Servers;
        }

        Message::ServerNameChanged(value) => {
            // Имя может содержать Unicode и обычные пробелы,
            // но не управляющие символы.
            //
            // Например допустимо:
            // "Germany Server"
            // "Сервер Германия"
            //
            // Но нельзя вставить перенос строки или NUL.
            if value.chars().count() <= MAX_SERVER_NAME_CHARS
                && !value.chars().any(char::is_control)
            {
                app.add_server.name = value;
                app.add_server.status = None;
            }
        }

        Message::ServerHostChanged(value) => {
            // Поле предназначено именно для IP-адреса.
            //
            // IPv4 использует:
            // 0-9 и .
            //
            // IPv6 дополнительно использует:
            // a-f / A-F, :, [ ]
            //
            // Поэтому строки вроде:
            // fdvg32
            // google.com
            // test123
            //
            // ввести нельзя.
            let valid_characters = value.chars().all(|c| {
                c.is_ascii_digit()
                    || matches!(c, 'a'..='f' | 'A'..='F')
                    || c == '.'
                    || c == ':'
                    || c == '['
                    || c == ']'
            });

            if value.chars().count() <= MAX_HOST_CHARS && valid_characters {
                app.add_server.host = value;
                app.add_server.status = None;
            }
        }

        Message::ServerPortChanged(value) => {
            // SSH port состоит только из цифр.
            //
            // Максимальное значение u16:
            // 65535
            //
            // Поэтому больше 5 символов вводить нет смысла.
            let valid = value.len() <= 5 && value.chars().all(|c| c.is_ascii_digit());

            if valid {
                app.add_server.port = value;
                app.add_server.status = None;
            }
        }

        Message::ServerUserChanged(value) => {
            // SSH username не должен содержать:
            // - пробелы;
            // - переводы строк;
            // - другие управляющие символы.
            let valid = value.chars().count() <= MAX_SSH_USER_CHARS
                && !value.chars().any(|c| c.is_whitespace() || c.is_control());

            if valid {
                app.add_server.user = value;
                app.add_server.status = None;
            }
        }

        Message::ServerPasswordChanged(value) => {
            // Пароль почти нельзя фильтровать.
            //
            // Реальный SSH password вполне может содержать:
            // ! @ # $ % ^ & *
            // пробелы
            // Unicode
            //
            // Поэтому ограничиваем только максимальную длину.
            if value.chars().count() <= MAX_PASSWORD_CHARS {
                app.add_server.password = value;
                app.add_server.status = None;
            }
        }

        Message::ValidateServer => {
            validate_server_form(app);
        }

        Message::Connect => {
            // Пока это только UI-заглушка.
            // Позже отправим IPC-команду hopper-service.
            app.tunnel_state = TunnelState::Connecting;
        }

        Message::Disconnect => {
            app.tunnel_state = TunnelState::Disconnected;
        }
    }

    Task::none()
}

/// Проверяем форму.
///
/// Никакого SSH здесь пока НЕТ.
/// Мы просто убеждаемся, что пользователь ввёл
/// корректные базовые значения.
fn validate_server_form(app: &mut HopperApp) {
    let port = match app.add_server.port.trim().parse::<u16>() {
        Ok(port) if port != 0 => port,

        _ => {
            app.add_server.status = Some("SSH port должен быть числом от 1 до 65535.".to_string());

            return;
        }
    };

    let result = ManualServerConnection::new(
        app.add_server.name.trim(),
        app.add_server.host.trim(),
        port,
        app.add_server.user.trim(),
        app.add_server.password.clone(),
    );

    match result {
        Ok(_connection) => {
            // ВАЖНО:
            // _connection сейчас специально никуда не сохраняем.
            //
            // На следующем этапе именно этот объект передадим
            // SSH-клиенту для Test Connection.
            app.add_server.status =
                Some("Поля корректны. Следующий этап — SSH Test Connection.".to_string());
        }

        Err(error) => {
            app.add_server.status = Some(error.to_string());
        }
    }
}

/// Главный view.
///
/// В зависимости от Screen рисуем соответствующий экран.
fn view(app: &HopperApp) -> Element<'_, Message> {
    let navigation = row![
        button("Home").on_press(Message::OpenHome),
        button("Servers").on_press(Message::OpenServers),
    ]
    .spacing(10);

    let page = match app.screen {
        Screen::Home => home_page(app),

        Screen::Servers => servers_page(),

        Screen::AddServer => add_server_page(app),
    };

    let content = column![
        text("Hopper Desktop").size(30),
        navigation,
        Space::new().height(12),
        page,
    ]
    .spacing(14)
    .padding(24)
    .max_width(850);

    container(content)
        .width(Fill)
        .height(Fill)
        .center_x(Fill)
        .into()
}

/// Главный экран.
fn home_page(app: &HopperApp) -> Element<'_, Message> {
    let status = match app.tunnel_state {
        TunnelState::Disconnected => "Disconnected",
        TunnelState::Connecting => "Connecting...",
        TunnelState::Connected => "Connected",
        TunnelState::Disconnecting => "Disconnecting...",
        TunnelState::Failed => "Connection failed",
    };

    column![
        text("VPN").size(24),
        text(format!("Status: {status}")),
        row![
            button("Connect").on_press(Message::Connect),
            button("Disconnect").on_press(Message::Disconnect),
        ]
        .spacing(10),
        Space::new().height(10),
        text(
            "VPN engine пока не подключён. \
             Сейчас строим серверную библиотеку и SSH слой."
        ),
    ]
    .spacing(14)
    .into()
}

/// Server Library.
///
/// Пока серверов ещё нет, поэтому показываем пустое состояние.
fn servers_page() -> Element<'static, Message> {
    column![
        row![
            text("Server Library").size(24),
            Space::new().width(Length::Fill),
            button("Add server").on_press(Message::OpenAddServer),
        ]
        .align_y(iced::Alignment::Center),
        Space::new().height(12),
        text("Сохранённых серверов пока нет."),
        text(
            "Следующим этапом добавим SSH Test Connection \
             и сохранение существующего Hopper server."
        ),
    ]
    .spacing(12)
    .into()
}

/// Экран ручного добавления существующего Hopper server.
fn add_server_page(app: &HopperApp) -> Element<'_, Message> {
    let name = text_input("Например: Germany 1", &app.add_server.name)
        .on_input(Message::ServerNameChanged)
        .padding(10);

    let host = text_input("IP или hostname", &app.add_server.host)
        .on_input(Message::ServerHostChanged)
        .padding(10);

    let port = text_input("22", &app.add_server.port)
        .on_input(Message::ServerPortChanged)
        .padding(10);

    let user = text_input("root", &app.add_server.user)
        .on_input(Message::ServerUserChanged)
        .padding(10);

    let password = text_input("SSH password", &app.add_server.password)
        .on_input(Message::ServerPasswordChanged)
        // Iced скрывает символы пароля.
        .secure(true)
        .padding(10);

    let status: Element<'_, Message> = match &app.add_server.status {
        Some(message) => text(message).into(),
        None => Space::new().height(1).into(),
    };

    column![
        text("Add existing Hopper server").size(24),
        text(
            "На этом этапе приложение ничего не устанавливает \
             и ничего не изменяет на сервере."
        ),
        Space::new().height(8),
        text("Server name"),
        name,
        text("IP / Host"),
        host,
        text("SSH port"),
        port,
        text("SSH user"),
        user,
        text("SSH password"),
        password,
        Space::new().height(8),
        status,
        row![
            button("Cancel").on_press(Message::CancelAddServer),
            // Пока это Validate.
            // На следующем этапе переименуем в Test connection.
            button("Validate").on_press(Message::ValidateServer),
        ]
        .spacing(10),
    ]
    .spacing(8)
    .into()
}

fn main() -> iced::Result {
    iced::application(HopperApp::default, update, view)
        .title("Hopper Desktop")
        .theme(Theme::Dark)
        .centered()
        .run()
}
