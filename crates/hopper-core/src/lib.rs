use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

mod validation;

pub use validation::{
    MAX_HOST_CHARS, MAX_PASSWORD_CHARS, MAX_SERVER_NAME_CHARS, MAX_SSH_USER_CHARS, normalize_host,
    normalize_ip_address, normalize_server_name, normalize_ssh_user, validate_password,
    validate_ssh_port,
};

/// Уникальный локальный ID сервера.
///
/// Этот ID не приходит от Hopper server.
/// Он нужен именно desktop-приложению для хранения серверов,
/// построения цепочек и ссылок между объектами.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerId(Uuid);

impl ServerId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ServerId {
    fn default() -> Self {
        Self::new()
    }
}

/// Постоянный профиль сервера.
///
/// ВАЖНО:
/// здесь специально нет password.
///
/// Пароль нужен только для первоначального SSH-подключения.
/// После того как мы подключимся к существующему Hopper server,
/// рабочая авторизация должна выполняться Hopper SSH key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerProfile {
    pub id: ServerId,

    /// Имя, которое видит пользователь.
    /// Например: "Germany Hetzner".
    pub name: String,

    /// IP-адрес или hostname сервера.
    pub host: String,

    /// SSH port. Обычно 22.
    pub port: u16,

    /// SSH username. Обычно root.
    pub user: String,
}

impl ServerProfile {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let name = name.into();
        let host = host.into();
        let user = user.into();

        // Нормализация и валидация происходят внутри core.
        //
        // Даже если позже появится другой UI, CLI или IPC-клиент,
        // некорректные данные всё равно не попадут в ServerProfile.
        let name = normalize_server_name(&name)?;
        let host = normalize_host(&host)?;
        let user = normalize_ssh_user(&user)?;

        validate_ssh_port(port)?;

        Ok(Self {
            id: ServerId::new(),
            name,
            host,
            port,
            user,
        })
    }
}

/// Уникальный идентификатор цепочки.
///
/// Hopper использует отдельный UUID для каждой chain.
/// Этот ID позже будет передаваться серверу при provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(Uuid);

impl ChainId {
    /// Создаёт новую независимую Hopper chain.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Self::new()
    }
}

/// Цепочка Hopper-серверов.
///
/// Порядок имеет значение:
///
/// servers[0]       = entry
/// servers[last]    = exit
///
/// Если сервер один:
///
/// servers[0] одновременно entry и exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopChain {
    pub id: ChainId,

    /// Отображаемое имя.
    ///
    /// Например:
    ///
    /// Germany -> Netherlands -> USA
    pub name: String,

    /// ServerId в порядке прохождения трафика:
    ///
    /// client -> servers[0] -> servers[1] -> ... -> exit
    pub servers: Vec<ServerId>,
}

impl HopChain {
    /// Создаёт Hopper chain.
    ///
    /// Пустая chain недопустима:
    /// даже single-hop VPN должен иметь один сервер.
    pub fn new(name: impl Into<String>, servers: Vec<ServerId>) -> Result<Self, CoreError> {
        let name = name.into();
        let name = name.trim();

        if name.is_empty() {
            return Err(CoreError::InvalidServer("chain name is empty"));
        }

        if servers.is_empty() {
            return Err(CoreError::InvalidServer(
                "chain must contain at least one server",
            ));
        }

        Ok(Self {
            id: ChainId::new(),
            name: name.to_string(),
            servers,
        })
    }

    /// Первый hop.
    pub fn entry(&self) -> &ServerId {
        // Constructor гарантирует, что servers не пустой.
        &self.servers[0]
    }

    /// Последний hop.
    pub fn exit(&self) -> &ServerId {
        self.servers
            .last()
            .expect("HopChain always contains at least one server")
    }

    /// Количество hops.
    pub fn hop_count(&self) -> usize {
        self.servers.len()
    }

    /// Provisioning Hopper выполняется с exit к entry.
    ///
    /// Поэтому даём готовый iterator в обратном порядке.
    pub fn provisioning_order(&self) -> impl DoubleEndedIterator<Item = &ServerId> {
        self.servers.iter().rev()
    }

    /// True для обычного single-hop.
    pub fn is_single_hop(&self) -> bool {
        self.servers.len() == 1
    }
}

/// Секретная строка.
///
/// Пока это обычный String в памяти, но Debug специально скрывает
/// содержимое, чтобы пароль случайно не оказался в логах.
///
/// ВАЖНО:
/// здесь НЕТ Serialize / Deserialize.
/// Мы специально не даём serde случайно записать пароль в JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Получить секрет как &str.
    ///
    /// Использовать только непосредственно перед передачей
    /// в SSH-библиотеку.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// Если кто-нибудь сделает:
//
//     println!("{:?}", password);
//
// реальный пароль не будет напечатан.
//
// Используем обычный комментарий `//`, а не `///`,
// потому что Rust пытается запускать код из документации
// как doctest.
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// Данные формы "Add existing server".
///
/// Эти данные существуют только во время добавления сервера.
/// Они НЕ являются постоянным Hopper profile.
#[derive(Debug, Clone)]
pub struct ManualServerConnection {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,

    /// Пароль живёт только в памяти.
    pub password: SecretString,
}

impl ManualServerConnection {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let name = name.into();
        let host = host.into();
        let user = user.into();

        let name = normalize_server_name(&name)?;
        let host = normalize_ip_address(&host)?;
        let user = normalize_ssh_user(&user)?;

        validate_ssh_port(port)?;

        let password = SecretString::new(password);

        validate_password(password.expose())?;

        Ok(Self {
            name,
            host,
            port,
            user,
            password,
        })
    }
}

/// Текущее состояние VPN.
///
/// Позже состояний станет больше:
/// - Provisioning
/// - Authenticating
/// - ConfiguringRoutes
/// - Reconnecting
///
/// Но пока оставляем минимальную модель.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TunnelState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

/// Ошибки core.
///
/// UI потом сможет преобразовывать их в понятные пользователю сообщения.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid server profile: {0}")]
    InvalidServer(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_server_profile() {
        let profile = ServerProfile::new("Germany", "192.0.2.10", 22, "root").unwrap();

        assert_eq!(profile.port, 22);
        assert_eq!(profile.user, "root");
    }

    #[test]
    fn rejects_empty_host() {
        let result = ServerProfile::new("Germany", "", 22, "root");

        assert_eq!(
            result.unwrap_err(),
            CoreError::InvalidServer("host is empty")
        );
    }

    #[test]
    fn creates_manual_server_connection() {
        let connection = ManualServerConnection::new(
            "Germany",
            "192.0.2.10",
            22,
            "root",
            "very-secret-password",
        )
        .unwrap();

        assert_eq!(connection.host, "192.0.2.10");
        assert_eq!(connection.password.expose(), "very-secret-password");
    }

    #[test]
    fn rejects_empty_password() {
        let result = ManualServerConnection::new("Germany", "192.0.2.10", 22, "root", "");

        assert_eq!(
            result.unwrap_err(),
            CoreError::InvalidServer("password is empty")
        );
    }

    #[test]
    fn password_is_redacted_in_debug_output() {
        let password = SecretString::new("super-secret");

        let debug_output = format!("{password:?}");

        assert!(!debug_output.contains("super-secret"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn accepts_ipv4_host() {
        let profile = ServerProfile::new("Germany", "192.168.1.10", 22, "root").unwrap();

        assert_eq!(profile.host, "192.168.1.10");
    }

    #[test]
    fn accepts_ipv6_host() {
        let profile = ServerProfile::new("IPv6 Server", "[2001:db8::1]", 22, "root").unwrap();

        // Квадратные скобки убираются при нормализации.
        assert_eq!(profile.host, "2001:db8::1");
    }

    #[test]
    fn accepts_hostname() {
        let profile = ServerProfile::new("Germany", "VPN.Example.COM", 22, "root").unwrap();

        assert_eq!(profile.host, "vpn.example.com");
    }

    #[test]
    fn rejects_url_instead_of_host() {
        let result = ServerProfile::new("Germany", "https://example.com", 22, "root");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_hostname_with_spaces() {
        let result = ServerProfile::new("Germany", "server example.com", 22, "root");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_hostname() {
        let result = ServerProfile::new("Germany", "-server.example.com", 22, "root");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_zero_port() {
        let result = ServerProfile::new("Germany", "example.com", 0, "root");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_user_with_spaces() {
        let result = ServerProfile::new("Germany", "example.com", 22, "root user");

        assert!(result.is_err());
    }

    #[test]
    fn trims_normal_fields() {
        let profile = ServerProfile::new("  Germany  ", "  example.com  ", 22, "  root  ").unwrap();

        assert_eq!(profile.name, "Germany");
        assert_eq!(profile.host, "example.com");
        assert_eq!(profile.user, "root");
    }

    #[test]
    fn password_may_contain_spaces() {
        let connection = ManualServerConnection::new(
            "Germany",
            "192.168.1.10",
            22,
            "root",
            " my complicated password ",
        )
        .unwrap();

        assert_eq!(connection.password.expose(), " my complicated password ");
    }

    #[test]
    fn manual_connection_accepts_ipv4() {
        let connection =
            ManualServerConnection::new("Germany", "192.168.1.10", 22, "root", "password").unwrap();

        assert_eq!(connection.host, "192.168.1.10");
    }

    #[test]
    fn manual_connection_accepts_ipv6() {
        let connection =
            ManualServerConnection::new("Germany", "2001:db8::1", 22, "root", "password").unwrap();

        assert_eq!(connection.host, "2001:db8::1");
    }

    #[test]
    fn manual_connection_rejects_hostname() {
        let result =
            ManualServerConnection::new("Germany", "server.example.com", 22, "root", "password");

        assert!(result.is_err());
    }

    #[test]
    fn manual_connection_rejects_random_string() {
        let result = ManualServerConnection::new("Germany", "fdvg32", 22, "root", "password");

        assert!(result.is_err());
    }

    #[test]
    fn manual_connection_rejects_invalid_ipv4() {
        let result =
            ManualServerConnection::new("Germany", "999.999.999.999", 22, "root", "password");

        assert!(result.is_err());
    }

    #[test]
    fn creates_single_hop_chain() {
        let server = ServerId::new();

        let chain = HopChain::new("Germany", vec![server]).unwrap();

        assert_eq!(chain.hop_count(), 1);
        assert!(chain.is_single_hop());

        assert_eq!(*chain.entry(), server);
        assert_eq!(*chain.exit(), server);
    }

    #[test]
    fn keeps_chain_order_from_entry_to_exit() {
        let entry = ServerId::new();
        let relay = ServerId::new();
        let exit = ServerId::new();

        let chain = HopChain::new("Three hop", vec![entry, relay, exit]).unwrap();

        assert_eq!(chain.hop_count(), 3);

        assert_eq!(*chain.entry(), entry);
        assert_eq!(*chain.exit(), exit);

        assert!(!chain.is_single_hop());
    }

    #[test]
    fn provisioning_order_is_exit_to_entry() {
        let entry = ServerId::new();
        let relay = ServerId::new();
        let exit = ServerId::new();

        let chain = HopChain::new("Three hop", vec![entry, relay, exit]).unwrap();

        let order: Vec<ServerId> = chain.provisioning_order().copied().collect();

        assert_eq!(order, vec![exit, relay, entry,]);
    }

    #[test]
    fn rejects_empty_chain() {
        let result = HopChain::new("Empty chain", vec![]);

        assert!(result.is_err());
    }
}
