use russh::client;
use russh::keys::PublicKeyOrCertificate;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

/// Информация о публичном SSH host key сервера.
///
/// Именно этот fingerprint позже будем сохранять локально,
/// чтобы при следующих соединениях проверять:
///
/// "это тот же сервер или его ключ неожиданно изменился?"
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyInfo {
    /// Тип SSH ключа.
    ///
    /// Например:
    /// ssh-ed25519
    /// ssh-rsa
    /// ecdsa-sha2-nistp256
    pub algorithm: String,

    /// SHA-256 fingerprint ключа.
    ///
    /// Например:
    /// SHA256:abc123...
    pub fingerprint: String,
}

/// Ошибки SSH probe.
///
/// Пока набор небольшой.
/// По мере реализации полноценного SSH-клиента
/// добавим отдельные ошибки authentication, protocol и т.д.
#[derive(Debug, Error)]
pub enum SshProbeError {
    #[error("SSH connection timed out")]
    Timeout,

    #[error("SSH connection failed: {0}")]
    Connection(String),

    #[error("SSH server did not provide a host key")]
    HostKeyNotReceived,
}

/// Handler для самого первого SSH соединения.
///
/// Его задача только одна:
///
/// получить публичный host key сервера.
///
/// Мы специально НЕ доверяем ключу автоматически.
/// Поэтому после получения fingerprint возвращаем `false`.
///
/// Это означает:
///
/// - пароль не отправляется;
/// - authentication не выполняется;
/// - команды не запускаются;
/// - VPS никак не изменяется.
struct ProbeHandler {
    observed_key: Arc<Mutex<Option<HostKeyInfo>>>,
}

impl client::Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // PublicKeyOrCertificate может содержать либо обычный SSH key,
        // либо SSH certificate.
        //
        // Для fingerprint нам нужен обычный public key.
        let public_key = server_public_key.public_key();

        // По умолчанию ssh-key использует SHA-256 fingerprint.
        let fingerprint = public_key.fingerprint(Default::default()).to_string();

        let info = HostKeyInfo {
            algorithm: public_key.algorithm().as_str().to_string(),
            fingerprint,
        };

        // Сохраняем увиденный ключ, чтобы вернуть его
        // функции probe_host_key после завершения handshake.
        if let Ok(mut observed_key) = self.observed_key.lock() {
            *observed_key = Some(info);
        }

        // ВАЖНО:
        //
        // Не делаем Ok(true)!
        //
        // Первый неизвестный ключ нельзя автоматически считать доверенным.
        Ok(false)
    }
}

/// Получает SSH host key удалённого сервера.
///
/// Эта функция выполняет только SSH handshake.
///
/// Она НЕ:
///
/// - отправляет username;
/// - отправляет password;
/// - открывает shell;
/// - запускает команды;
/// - читает файлы;
/// - изменяет сервер.
///
/// `timeout_duration` защищает приложение от зависания,
/// если IP существует, но SSH не отвечает.
pub async fn probe_host_key(
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<HostKeyInfo, SshProbeError> {
    let observed_key = Arc::new(Mutex::new(None));

    let handler = ProbeHandler {
        observed_key: Arc::clone(&observed_key),
    };

    // Пока используем стандартные безопасные настройки russh.
    let config = Arc::new(client::Config::default());

    let connection = client::connect(config, (host, port), handler);

    // Ограничиваем максимальное время подключения.
    let connection_result = timeout(timeout_duration, connection)
        .await
        .map_err(|_| SshProbeError::Timeout)?;

    // check_server_key вызывается во время SSH handshake.
    //
    // Мы намеренно возвращаем из него false,
    // поэтому client::connect скорее всего завершится ошибкой
    // "ключ не принят".
    //
    // Но fingerprint к этому моменту уже получен.
    if let Ok(observed_key) = observed_key.lock()
        && let Some(key) = observed_key.clone()
    {
        return Ok(key);
    }

    // Если до host key мы вообще не дошли,
    // показываем настоящую причину ошибки подключения.
    match connection_result {
        Ok(_) => Err(SshProbeError::HostKeyNotReceived),

        Err(error) => Err(SshProbeError::Connection(error.to_string())),
    }
}
