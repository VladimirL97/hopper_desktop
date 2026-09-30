use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Уникальный локальный ID сервера.
///
/// Этот ID не приходит от Hopper server.
/// Он нужен именно desktop-приложению для хранения серверов,
/// построения цепочек и ссылок между объектами.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

        validate_basic_server_fields(&name, &host, port, &user)?;

        Ok(Self {
            id: ServerId::new(),
            name,
            host,
            port,
            user,
        })
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
        let password = SecretString::new(password);

        validate_basic_server_fields(&name, &host, port, &user)?;

        if password.is_empty() {
            return Err(CoreError::InvalidServer("password is empty"));
        }

        Ok(Self {
            name,
            host,
            port,
            user,
            password,
        })
    }
}

/// Проверяем общие поля.
///
/// Вынесено отдельно, потому что эти же проверки нужны:
/// - постоянному ServerProfile;
/// - форме ручного подключения;
/// - позже импорту Hopper profile v2.
fn validate_basic_server_fields(
    name: &str,
    host: &str,
    port: u16,
    user: &str,
) -> Result<(), CoreError> {
    if name.trim().is_empty() {
        return Err(CoreError::InvalidServer("name is empty"));
    }

    if host.trim().is_empty() {
        return Err(CoreError::InvalidServer("host is empty"));
    }

    if user.trim().is_empty() {
        return Err(CoreError::InvalidServer("user is empty"));
    }

    if port == 0 {
        return Err(CoreError::InvalidServer("port must be non-zero"));
    }

    Ok(())
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
}
