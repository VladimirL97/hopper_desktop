use crate::CoreError;
use std::net::IpAddr;

// Максимальная длина отображаемого имени сервера.
pub const MAX_SERVER_NAME_CHARS: usize = 80;

// DNS hostname по стандарту не должен быть бесконечным.
// Для наших целей 253 символа достаточно.
pub const MAX_HOST_CHARS: usize = 253;

// Linux/SSH username обычно гораздо короче,
// но 64 символа оставляет хороший запас.
pub const MAX_SSH_USER_CHARS: usize = 64;

// Пароль специально почти не ограничиваем по символам.
//
// Пароль может содержать:
// - пробелы;
// - специальные символы;
// - Unicode.
//
// Ограничиваем только размер, чтобы нельзя было случайно
// вставить мегабайты текста в поле.
pub const MAX_PASSWORD_CHARS: usize = 4096;

/// Проверяет и нормализует имя сервера.
///
/// Убирает пробелы в начале и конце строки.
///
/// Пример преобразования:
// "  Germany 1  " -> "Germany 1"
pub fn normalize_server_name(value: &str) -> Result<String, CoreError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(CoreError::InvalidServer("server name is empty"));
    }

    if value.chars().count() > MAX_SERVER_NAME_CHARS {
        return Err(CoreError::InvalidServer("server name is too long"));
    }

    // Управляющие символы вроде \n, \r, \0 нам здесь не нужны.
    if value.chars().any(char::is_control) {
        return Err(CoreError::InvalidServer(
            "server name contains control characters",
        ));
    }

    Ok(value.to_string())
}

/// Проверяет IP-адрес или DNS hostname.
///
/// Поддерживаются IPv4, IPv6 и обычные DNS hostname.
///
/// Примеры допустимых значений:
// 192.168.1.10
// 1.2.3.4
// server.example.com
// vpn.example.com
// 2001:db8::1
// [2001:db8::1]
//
// Примеры недопустимых значений:
// https://server.com
// server com
// -server.com
// server..com
pub fn normalize_host(value: &str) -> Result<String, CoreError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(CoreError::InvalidServer("host is empty"));
    }

    if value.chars().count() > MAX_HOST_CHARS {
        return Err(CoreError::InvalidServer("host is too long"));
    }

    if value.chars().any(char::is_whitespace) {
        return Err(CoreError::InvalidServer("host contains whitespace"));
    }

    // Разрешаем запись IPv6 как:
    //
    //     [2001:db8::1]
    //
    // Но внутри приложения будем хранить:
    //
    //     2001:db8::1
    let ip_candidate = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else {
        value
    };

    // Сначала пробуем IPv4 / IPv6.
    if let Ok(ip) = ip_candidate.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }

    // Пока используем обычные ASCII DNS names.
    //
    // International Domain Names при необходимости позже
    // добавим через IDNA/punycode.
    if !value.is_ascii() {
        return Err(CoreError::InvalidServer(
            "hostname must contain ASCII characters",
        ));
    }

    // Пользователь может написать FQDN с точкой в конце:
    //
    //     server.example.com.
    //
    // Хранить её нам незачем.
    let hostname = value.strip_suffix('.').unwrap_or(value);

    if hostname.is_empty() {
        return Err(CoreError::InvalidServer("hostname is empty"));
    }

    // Проверяем каждую DNS label отдельно.
    for label in hostname.split('.') {
        if label.is_empty() {
            return Err(CoreError::InvalidServer("hostname contains an empty label"));
        }

        if label.len() > 63 {
            return Err(CoreError::InvalidServer("hostname label is too long"));
        }

        let bytes = label.as_bytes();

        // DNS label не должна начинаться или заканчиваться дефисом.
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err(CoreError::InvalidServer(
                "hostname label cannot start or end with '-'",
            ));
        }

        // Обычный hostname:
        //
        // A-Z
        // a-z
        // 0-9
        // -
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(CoreError::InvalidServer(
                "hostname contains invalid characters",
            ));
        }
    }

    // DNS hostname регистронезависим.
    Ok(hostname.to_ascii_lowercase())
}

// Проверяем SSH username.
pub fn normalize_ssh_user(value: &str) -> Result<String, CoreError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(CoreError::InvalidServer("SSH user is empty"));
    }

    if value.chars().count() > MAX_SSH_USER_CHARS {
        return Err(CoreError::InvalidServer("SSH user is too long"));
    }

    // В username не разрешаем пробелы.
    if value.chars().any(char::is_whitespace) {
        return Err(CoreError::InvalidServer("SSH user contains whitespace"));
    }

    if value.chars().any(char::is_control) {
        return Err(CoreError::InvalidServer(
            "SSH user contains control characters",
        ));
    }

    Ok(value.to_string())
}

// SSH port.
//
// Поскольку тип u16 физически не может быть больше 65535,
// нам остаётся запретить только 0.
pub fn validate_ssh_port(port: u16) -> Result<(), CoreError> {
    if port == 0 {
        return Err(CoreError::InvalidServer(
            "SSH port must be between 1 and 65535",
        ));
    }

    Ok(())
}

/// Пароль не нормализуется и не обрезается.
///
/// Пробелы в начале и конце являются частью пароля.
//
// Например:
//
// " password "
//
// и:
//
// "password"
//
// это потенциально два разных пароля.
pub fn validate_password(value: &str) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::InvalidServer("password is empty"));
    }

    if value.chars().count() > MAX_PASSWORD_CHARS {
        return Err(CoreError::InvalidServer("password is too long"));
    }

    Ok(())
}

/// Проверяет именно IP-адрес.
///
/// Поддерживает:
/// - IPv4
/// - IPv6
/// - IPv6 в квадратных скобках
///
/// Hostname здесь специально НЕ принимается.
pub fn normalize_ip_address(value: &str) -> Result<String, CoreError> {
    let value = value.trim();

    if value.is_empty() {
        return Err(CoreError::InvalidServer("IP address is empty"));
    }

    // Для IPv6 пользователь может вставить:
    //
    // [2001:db8::1]
    //
    // Убираем квадратные скобки перед parse.
    let candidate = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else {
        value
    };

    let ip = candidate
        .parse::<IpAddr>()
        .map_err(|_| CoreError::InvalidServer("invalid IP address"))?;

    Ok(ip.to_string())
}
