use russh::ChannelMsg;
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

#[derive(Debug, Error)]
pub enum HopperInspectionError {
    #[error(transparent)]
    Auth(#[from] SshAuthError),

    #[error(transparent)]
    Command(#[from] SshCommandError),

    /// Обязательное поле отсутствует в выводе inspection.
    #[error("inspection output is missing required field: {0}")]
    MissingField(&'static str),

    /// VERSION.json существует, но его содержимое
    /// не удалось разобрать как HopperVersionInfo.
    #[error("invalid Hopper VERSION.json: {0}")]
    InvalidVersionJson(String),
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

/// Ошибки проверки SSH authentication.
///
/// Здесь специально разделяем:
///
/// - сетевую ошибку;
/// - изменение host key;
/// - неправильный login/password.
///
/// Позже UI сможет показывать пользователю
/// разные понятные сообщения.
#[derive(Debug, Error)]
pub enum SshAuthError {
    #[error("SSH connection timed out")]
    Timeout,

    #[error("SSH connection failed: {0}")]
    Connection(String),

    #[error("SSH host key mismatch. Expected {expected}, received {actual}")]
    HostKeyMismatch { expected: String, actual: String },

    #[error("SSH authentication was rejected")]
    AuthenticationRejected,

    #[error("SSH authentication failed: {0}")]
    Authentication(String),
}

/// Результат выполнения одной фиксированной SSH-команды.
///
/// Этот тип позже пригодится не только inspection,
/// но и provisioning Hopper.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub exit_status: Option<u32>,
}

/// Диагностическая информация о файловой структуре Hopper.
///
/// Используется только во время разработки, чтобы понять,
/// как реально выглядит уже существующий Hopper server.
///
/// Никакие файлы не изменяются.
#[derive(Debug, Clone)]
pub struct HopperLayoutDiagnostic {
    pub output: String,
}

/// Ошибки выполнения SSH-команды.
#[derive(Debug, Error)]
pub enum SshCommandError {
    #[error("SSH command timed out")]
    Timeout,

    #[error("could not open SSH channel: {0}")]
    OpenChannel(String),

    #[error("could not execute SSH command: {0}")]
    Execute(String),

    #[error("SSH channel closed unexpectedly")]
    ChannelClosed,
}

/// Handler для уже ДОВЕРЕННОГО сервера.
///
/// В отличие от ProbeHandler он принимает host key
/// только в том случае, если fingerprint точно совпадает
/// с fingerprint, который пользователь видел раньше.
///
/// Никакого "accept all".
struct TrustedHostHandler {
    expected_fingerprint: String,

    /// Запоминаем реально присланный сервером ключ,
    /// чтобы в случае mismatch показать его пользователю.
    observed_key: Arc<Mutex<Option<HostKeyInfo>>>,
}

impl client::Handler for TrustedHostHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let public_key = server_public_key.public_key();

        let fingerprint = public_key.fingerprint(Default::default()).to_string();

        let info = HostKeyInfo {
            algorithm: public_key.algorithm().as_str().to_string(),
            fingerprint: fingerprint.clone(),
        };

        if let Ok(mut observed_key) = self.observed_key.lock() {
            *observed_key = Some(info);
        }

        // Доверяем серверу ТОЛЬКО если fingerprint
        // совпадает с ранее подтверждённым.
        Ok(fingerprint == self.expected_fingerprint)
    }
}

/// Проверяет login/password существующего SSH-сервера.
///
/// ВАЖНО:
///
/// Эта функция НЕ:
///
/// - открывает shell;
/// - выполняет команды;
/// - запускает start_server.sh;
/// - читает файлы;
/// - пишет файлы;
/// - меняет iptables;
/// - устанавливает Hopper.
///
/// Она делает только:
///
/// TCP
///   -> SSH handshake
///   -> host key verification
///   -> password authentication
///   -> disconnect
pub async fn test_password_authentication(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    expected_fingerprint: &str,
    timeout_duration: Duration,
) -> Result<(), SshAuthError> {
    let observed_key = Arc::new(Mutex::new(None));

    let handler = TrustedHostHandler {
        expected_fingerprint: expected_fingerprint.to_string(),
        observed_key: Arc::clone(&observed_key),
    };

    let config = Arc::new(client::Config::default());

    // ---------------------------------------------------------
    // ЭТАП 1:
    // SSH connect + обязательная проверка host key.
    // ---------------------------------------------------------

    let connect_result = timeout(
        timeout_duration,
        client::connect(config, (host, port), handler),
    )
    .await
    .map_err(|_| SshAuthError::Timeout)?;

    let mut session = match connect_result {
        Ok(session) => session,

        Err(error) => {
            // Если сервер успел прислать host key,
            // проверяем, не был ли причиной ошибки mismatch.
            let actual_fingerprint = observed_key
                .lock()
                .ok()
                .and_then(|key| key.clone())
                .map(|key| key.fingerprint);

            if let Some(actual) = actual_fingerprint
                && actual != expected_fingerprint
            {
                return Err(SshAuthError::HostKeyMismatch {
                    expected: expected_fingerprint.to_string(),
                    actual,
                });
            }

            return Err(SshAuthError::Connection(error.to_string()));
        }
    };

    // ---------------------------------------------------------
    // ЭТАП 2:
    // Только после успешной проверки host key
    // разрешаем password authentication.
    // ---------------------------------------------------------

    let auth_result = timeout(
        timeout_duration,
        session.authenticate_password(user.to_string(), password.to_string()),
    )
    .await
    .map_err(|_| SshAuthError::Timeout)?
    .map_err(|error| SshAuthError::Authentication(error.to_string()))?;

    let authenticated = auth_result.success();

    // Мы только проверяем credentials.
    //
    // Shell и SSH channel здесь не открываются.
    //
    // Независимо от результата authentication
    // аккуратно закрываем SSH session.
    let _ = session
        .disconnect(
            russh::Disconnect::ByApplication,
            "Hopper authentication test complete",
            "",
        )
        .await;

    if authenticated {
        Ok(())
    } else {
        Err(SshAuthError::AuthenticationRejected)
    }
}

/// Выполняет команду внутри уже authenticated SSH session.
///
/// ВАЖНО:
/// эта функция сама по себе универсальная.
/// Поэтому наружу из crate мы её пока не экспортируем.
///
/// UI не должен иметь возможность передавать сюда
/// произвольную строку shell-команды.
async fn execute_command(
    session: &client::Handle<TrustedHostHandler>,
    command: &str,
    timeout_duration: Duration,
) -> Result<CommandOutput, SshCommandError> {
    let future = async {
        // Открываем стандартный SSH session channel.
        let mut channel = session
            .channel_open_session()
            .await
            .map_err(|error| SshCommandError::OpenChannel(error.to_string()))?;

        // `true` означает, что мы хотим получить подтверждение
        // от SSH-сервера на exec request.
        channel
            .exec(true, command)
            .await
            .map_err(|error| SshCommandError::Execute(error.to_string()))?;

        let mut stdout = Vec::new();
        let mut exit_status = None;

        // Читаем события до закрытия канала.
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    stdout.extend_from_slice(&data);
                }

                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => {
                    exit_status = Some(status);
                }

                _ => {
                    // Остальные SSH channel events
                    // для read-only inspection нам пока не нужны.
                }
            }
        }

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            exit_status,
        })
    };

    timeout(timeout_duration, future)
        .await
        .map_err(|_| SshCommandError::Timeout)?
}

/// Показывает структуру существующей установки Hopper.
///
/// ВАЖНО:
/// команда полностью фиксированная.
/// Пользовательский ввод в shell-команду не подставляется.
///
/// Выполняются только read-only операции:
///
/// - uname
/// - cat VERSION.json
/// - find
/// - ls
pub async fn diagnose_hopper_layout(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    expected_fingerprint: &str,
    timeout_duration: Duration,
) -> Result<HopperLayoutDiagnostic, HopperInspectionError> {
    let observed_key = Arc::new(Mutex::new(None));

    let handler = TrustedHostHandler {
        expected_fingerprint: expected_fingerprint.to_string(),
        observed_key: Arc::clone(&observed_key),
    };

    let config = Arc::new(client::Config::default());

    let connect_result = timeout(
        timeout_duration,
        client::connect(config, (host, port), handler),
    )
    .await
    .map_err(|_| SshAuthError::Timeout)?;

    let mut session = match connect_result {
        Ok(session) => session,

        Err(error) => {
            let actual_fingerprint = observed_key
                .lock()
                .ok()
                .and_then(|key| key.clone())
                .map(|key| key.fingerprint);

            if let Some(actual) = actual_fingerprint
                && actual != expected_fingerprint
            {
                return Err(SshAuthError::HostKeyMismatch {
                    expected: expected_fingerprint.to_string(),
                    actual,
                }
                .into());
            }

            return Err(SshAuthError::Connection(error.to_string()).into());
        }
    };

    let auth_result = timeout(
        timeout_duration,
        session.authenticate_password(user.to_string(), password.to_string()),
    )
    .await
    .map_err(|_| SshAuthError::Timeout)?
    .map_err(|error| SshAuthError::Authentication(error.to_string()))?;

    if !auth_result.success() {
        return Err(SshAuthError::AuthenticationRejected.into());
    }

    // Только чтение.
    //
    // Private key специально НЕ читаем и НЕ выводим.
    const DIAGNOSTIC_COMMAND: &str = r#"
echo '=== SYSTEM ==='
uname -a 2>/dev/null || true

echo
echo '=== VERSION.json ==='
if test -f "$HOME/hopper/VERSION.json"; then
    cat "$HOME/hopper/VERSION.json"
else
    echo 'not found'
fi

echo
echo '=== ~/hopper ==='
find "$HOME/hopper" \
    -maxdepth 3 \
    -printf '%y %P\n' \
    2>/dev/null \
    | sort

echo
echo '=== ~/.hopper ==='
find "$HOME/.hopper" \
    -maxdepth 3 \
    -printf '%y %P\n' \
    2>/dev/null \
    | sort

echo
echo '=== Hopper scripts anywhere under ~/hopper ==='
find "$HOME/hopper" \
    -maxdepth 4 \
    -type f \
    \( \
        -name 'start_server.sh' \
        -o -name 'configure_server.sh' \
        -o -name 'hopper_common.sh' \
    \) \
    -print \
    2>/dev/null
"#;

    let result = execute_command(&session, DIAGNOSTIC_COMMAND, timeout_duration).await?;

    let _ = session
        .disconnect(
            russh::Disconnect::ByApplication,
            "Hopper layout diagnostic complete",
            "",
        )
        .await;

    Ok(HopperLayoutDiagnostic {
        output: result.stdout,
    })
}

/// Информация из Hopper VERSION.json.
///
/// Это позволяет desktop-клиенту понимать,
/// совместим ли сервер с нашей версией протокола.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopperVersionInfo {
    pub version: String,
    pub min_app_version: String,
    pub min_server_version: String,
    pub protocol_version: u32,

    pub git_remote: Option<String>,
    pub git_subdir: Option<String>,
    pub release_base_url: Option<String>,
}

/// Какая архитектура установки Hopper обнаружена.
///
/// ModernCli:
/// Hopper 3.x с hopperctl + Python command modules.
///
/// LegacyScripts:
/// старая установка со start_server.sh и другими shell scripts.
///
/// Unknown:
/// что-то Hopper-подобное есть, но мы не можем уверенно
/// определить поддерживаемую структуру.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopperLayoutKind {
    ModernCli,
    LegacyScripts,
    Unknown,
}

/// Результат безопасной проверки Hopper server.
///
/// Здесь только информация о наличии файлов.
/// Содержимое private key сюда НЕ попадает.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopperServerInspection {
    pub os: String,
    pub architecture: String,

    /// Содержимое VERSION.json после безопасного JSON parsing.
    pub version: Option<HopperVersionInfo>,

    pub hopper_directory: bool,

    // ---------------------------------------------------------
    // Hopper 3.x
    // ---------------------------------------------------------
    pub hopperctl: bool,

    pub command_start: bool,
    pub command_configure: bool,
    pub command_status: bool,
    pub command_install: bool,
    pub command_update: bool,

    // ---------------------------------------------------------
    // hopperd binaries
    // ---------------------------------------------------------
    pub hopperd_amd64: bool,
    pub hopperd_arm64: bool,

    // ---------------------------------------------------------
    // Hopper state
    // ---------------------------------------------------------
    pub hop_private_key: bool,
    pub hop_public_key: bool,
    pub registry_file: bool,
    pub chains_directory: bool,

    // ---------------------------------------------------------
    // Старый layout.
    //
    // Пока оставляем для будущей backward compatibility.
    // ---------------------------------------------------------
    pub legacy_start_script: bool,
    pub legacy_configure_script: bool,
    pub legacy_common_script: bool,
}

impl HopperServerInspection {
    /// Определяем тип установленного Hopper.
    pub fn layout_kind(&self) -> HopperLayoutKind {
        let modern = self.hopperctl && self.command_start && self.command_configure;

        if modern {
            return HopperLayoutKind::ModernCli;
        }

        let legacy =
            self.legacy_start_script && self.legacy_configure_script && self.legacy_common_script;

        if legacy {
            return HopperLayoutKind::LegacyScripts;
        }

        HopperLayoutKind::Unknown
    }

    /// Проверяет наличие hopperd именно для архитектуры сервера.
    pub fn has_native_hopperd(&self) -> bool {
        match self.architecture.as_str() {
            "x86_64" | "amd64" => self.hopperd_amd64,

            "aarch64" | "arm64" => self.hopperd_arm64,

            _ => false,
        }
    }

    /// Минимальная проверка того, что это рабочая
    /// существующая установка Hopper.
    pub fn looks_like_hopper(&self) -> bool {
        if self.os != "Linux" {
            return false;
        }

        if !self.hopper_directory {
            return false;
        }

        if self.version.is_none() {
            return false;
        }

        if !self.has_native_hopperd() {
            return false;
        }

        if !self.hop_private_key {
            return false;
        }

        matches!(
            self.layout_kind(),
            HopperLayoutKind::ModernCli | HopperLayoutKind::LegacyScripts
        )
    }
}

/// Проверяет существующую установку Hopper.
///
/// НИКАКИХ изменений на сервере.
///
/// Используются только:
///
/// - uname
/// - test
/// - printf
///
/// Не запускаются:
///
/// - configure_server.sh
/// - start_server.sh
/// - hopperd
/// - chmod
/// - apt
/// - iptables
pub async fn inspect_hopper_server(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    expected_fingerprint: &str,
    timeout_duration: Duration,
) -> Result<HopperServerInspection, HopperInspectionError> {
    let observed_key = Arc::new(Mutex::new(None));

    let handler = TrustedHostHandler {
        expected_fingerprint: expected_fingerprint.to_string(),
        observed_key: Arc::clone(&observed_key),
    };

    let config = Arc::new(client::Config::default());

    // Сначала обычное защищённое SSH-соединение.
    let connect_result = timeout(
        timeout_duration,
        client::connect(config, (host, port), handler),
    )
    .await
    .map_err(|_| SshAuthError::Timeout)?;

    let mut session = match connect_result {
        Ok(session) => session,

        Err(error) => {
            let actual_fingerprint = observed_key
                .lock()
                .ok()
                .and_then(|key| key.clone())
                .map(|key| key.fingerprint);

            if let Some(actual) = actual_fingerprint
                && actual != expected_fingerprint
            {
                return Err(SshAuthError::HostKeyMismatch {
                    expected: expected_fingerprint.to_string(),
                    actual,
                }
                .into());
            }

            return Err(SshAuthError::Connection(error.to_string()).into());
        }
    };

    // Только после проверки host key отправляем пароль.
    let auth_result = timeout(
        timeout_duration,
        session.authenticate_password(user.to_string(), password.to_string()),
    )
    .await
    .map_err(|_| SshAuthError::Timeout)?
    .map_err(|error| SshAuthError::Authentication(error.to_string()))?;

    if !auth_result.success() {
        return Err(SshAuthError::AuthenticationRejected.into());
    }

    // Команда специально полностью фиксированная.
    //
    // Никакой пользовательский input сюда не подставляется,
    // поэтому здесь нет shell injection.
    const INSPECTION_COMMAND: &str = r#"
printf 'os=%s\n' "$(uname -s 2>/dev/null || true)"
printf 'arch=%s\n' "$(uname -m 2>/dev/null || true)"

test -d "$HOME/hopper" \
  && echo 'hopper_directory=1' \
  || echo 'hopper_directory=0'

# ------------------------------------------------------------
# Hopper 3.x CLI layout
# ------------------------------------------------------------

test -f "$HOME/hopper/hopperctl" \
  && echo 'hopperctl=1' \
  || echo 'hopperctl=0'

test -f "$HOME/hopper/hopper/commands/start.py" \
  && echo 'command_start=1' \
  || echo 'command_start=0'

test -f "$HOME/hopper/hopper/commands/configure.py" \
  && echo 'command_configure=1' \
  || echo 'command_configure=0'

test -f "$HOME/hopper/hopper/commands/status.py" \
  && echo 'command_status=1' \
  || echo 'command_status=0'

test -f "$HOME/hopper/hopper/commands/install.py" \
  && echo 'command_install=1' \
  || echo 'command_install=0'

test -f "$HOME/hopper/hopper/commands/update.py" \
  && echo 'command_update=1' \
  || echo 'command_update=0'

# ------------------------------------------------------------
# hopperd
# ------------------------------------------------------------

test -f "$HOME/hopper/dist/hopperd-linux-amd64" \
  && echo 'hopperd_amd64=1' \
  || echo 'hopperd_amd64=0'

test -f "$HOME/hopper/dist/hopperd-linux-arm64" \
  && echo 'hopperd_arm64=1' \
  || echo 'hopperd_arm64=0'

# ------------------------------------------------------------
# Hopper state
# ------------------------------------------------------------

test -f "$HOME/.hopper/id_ed25519" \
  && echo 'hop_private_key=1' \
  || echo 'hop_private_key=0'

test -f "$HOME/.hopper/id_ed25519.pub" \
  && echo 'hop_public_key=1' \
  || echo 'hop_public_key=0'

test -f "$HOME/.hopper/registry.json" \
  && echo 'registry_file=1' \
  || echo 'registry_file=0'

test -d "$HOME/.hopper/chains" \
  && echo 'chains_directory=1' \
  || echo 'chains_directory=0'

# ------------------------------------------------------------
# Legacy Hopper
# ------------------------------------------------------------

test -f "$HOME/hopper/start_server.sh" \
  && echo 'legacy_start_script=1' \
  || echo 'legacy_start_script=0'

test -f "$HOME/hopper/configure_server.sh" \
  && echo 'legacy_configure_script=1' \
  || echo 'legacy_configure_script=0'

test -f "$HOME/hopper/hopper_common.sh" \
  && echo 'legacy_common_script=1' \
  || echo 'legacy_common_script=0'

# ------------------------------------------------------------
# VERSION.json
#
# Убираем переводы строк, чтобы JSON находился
# целиком в одном protocol line.
# ------------------------------------------------------------

if test -f "$HOME/hopper/VERSION.json"; then
    printf 'version_json='
    tr -d '\r\n' < "$HOME/hopper/VERSION.json"
    printf '\n'
else
    echo 'version_json='
fi
"#;

    let output = execute_command(&session, INSPECTION_COMMAND, timeout_duration).await?;

    // Закрываем SSH сразу после inspection.
    let _ = session
        .disconnect(
            russh::Disconnect::ByApplication,
            "Hopper inspection complete",
            "",
        )
        .await;

    parse_inspection_output(&output.stdout)
}

fn parse_inspection_output(output: &str) -> Result<HopperServerInspection, HopperInspectionError> {
    let mut os = None;
    let mut architecture = None;

    let mut version = None;

    let mut hopper_directory = false;

    let mut hopperctl = false;

    let mut command_start = false;
    let mut command_configure = false;
    let mut command_status = false;
    let mut command_install = false;
    let mut command_update = false;

    let mut hopperd_amd64 = false;
    let mut hopperd_arm64 = false;

    let mut hop_private_key = false;
    let mut hop_public_key = false;
    let mut registry_file = false;
    let mut chains_directory = false;

    let mut legacy_start_script = false;
    let mut legacy_configure_script = false;
    let mut legacy_common_script = false;

    for raw_line in output.lines() {
        // Защищаемся от:
        //
        // - CRLF (\r\n)
        // - случайных пробелов
        // - отступов в тестовых строках
        let line = raw_line.trim();

        if line.is_empty() {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };

        let key = raw_key.trim();
        let value = raw_value.trim();

        match key {
            "os" => {
                os = Some(value.to_string());
            }

            "arch" => {
                architecture = Some(value.to_string());
            }

            "version_json" => {
                let value = value.trim();

                if !value.is_empty() {
                    let parsed: HopperVersionInfo =
                        serde_json::from_str(value).map_err(|error| {
                            HopperInspectionError::InvalidVersionJson(error.to_string())
                        })?;

                    version = Some(parsed);
                }
            }

            "hopper_directory" => {
                hopper_directory = value == "1";
            }

            "hopperctl" => {
                hopperctl = value == "1";
            }

            "command_start" => {
                command_start = value == "1";
            }

            "command_configure" => {
                command_configure = value == "1";
            }

            "command_status" => {
                command_status = value == "1";
            }

            "command_install" => {
                command_install = value == "1";
            }

            "command_update" => {
                command_update = value == "1";
            }

            "hopperd_amd64" => {
                hopperd_amd64 = value == "1";
            }

            "hopperd_arm64" => {
                hopperd_arm64 = value == "1";
            }

            "hop_private_key" => {
                hop_private_key = value == "1";
            }

            "hop_public_key" => {
                hop_public_key = value == "1";
            }

            "registry_file" => {
                registry_file = value == "1";
            }

            "chains_directory" => {
                chains_directory = value == "1";
            }

            "legacy_start_script" => {
                legacy_start_script = value == "1";
            }

            "legacy_configure_script" => {
                legacy_configure_script = value == "1";
            }

            "legacy_common_script" => {
                legacy_common_script = value == "1";
            }

            _ => {}
        }
    }

    Ok(HopperServerInspection {
        os: os.ok_or(HopperInspectionError::MissingField("os"))?,

        architecture: architecture.ok_or(HopperInspectionError::MissingField("arch"))?,

        version,

        hopper_directory,

        hopperctl,

        command_start,
        command_configure,
        command_status,
        command_install,
        command_update,

        hopperd_amd64,
        hopperd_arm64,

        hop_private_key,
        hop_public_key,
        registry_file,
        chains_directory,

        legacy_start_script,
        legacy_configure_script,
        legacy_common_script,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modern_hopper_server() {
        // Не пишем JSON вручную.
        //
        // Сериализуем ту же структуру, которую production-код
        // потом должен десериализовать.
        let version = HopperVersionInfo {
            version: "3.1.1".to_string(),
            min_app_version: "3.1.0".to_string(),
            min_server_version: "3.1.0".to_string(),
            protocol_version: 2,

            git_remote: Some("https://github.com/ZonD80/hopper.git".to_string()),

            git_subdir: Some("server".to_string()),

            release_base_url: Some(
                "https://github.com/ZonD80/hopper/releases/latest/download".to_string(),
            ),
        };

        let version_json = serde_json::to_string(&version).unwrap();

        let output = format!(
            "\
    os=Linux
    arch=x86_64
    hopper_directory=1
    hopperctl=1
    command_start=1
    command_configure=1
    command_status=1
    command_install=1
    command_update=1
    hopperd_amd64=1
    hopperd_arm64=0
    hop_private_key=1
    hop_public_key=1
    registry_file=1
    chains_directory=1
    legacy_start_script=0
    legacy_configure_script=0
    legacy_common_script=0
    version_json={version_json}
    "
        );

        let inspection = parse_inspection_output(&output).unwrap();

        assert_eq!(inspection.os, "Linux");
        assert_eq!(inspection.architecture, "x86_64");

        assert_eq!(inspection.layout_kind(), HopperLayoutKind::ModernCli);

        assert!(inspection.hopperctl);
        assert!(inspection.command_start);
        assert!(inspection.command_configure);
        assert!(inspection.command_status);
        assert!(inspection.command_install);
        assert!(inspection.command_update);

        assert!(inspection.hopperd_amd64);
        assert!(!inspection.hopperd_arm64);

        assert!(inspection.hop_private_key);
        assert!(inspection.hop_public_key);
        assert!(inspection.registry_file);
        assert!(inspection.chains_directory);

        let version = inspection.version.as_ref().unwrap();

        assert_eq!(version.version, "3.1.1");
        assert_eq!(version.min_app_version, "3.1.0");
        assert_eq!(version.min_server_version, "3.1.0");
        assert_eq!(version.protocol_version, 2);

        assert_eq!(version.git_subdir.as_deref(), Some("server"));

        assert!(inspection.looks_like_hopper());
    }

    #[test]
    fn rejects_incomplete_modern_hopper_server() {
        let version = HopperVersionInfo {
            version: "3.1.1".to_string(),
            min_app_version: "3.1.0".to_string(),
            min_server_version: "3.1.0".to_string(),
            protocol_version: 2,

            git_remote: None,
            git_subdir: None,
            release_base_url: None,
        };

        let version_json = serde_json::to_string(&version).unwrap();

        let output = format!(
            "\
    os=Linux
    arch=x86_64
    hopper_directory=1
    hopperctl=1
    command_start=0
    command_configure=1
    command_status=1
    command_install=1
    command_update=1
    hopperd_amd64=1
    hopperd_arm64=0
    hop_private_key=1
    hop_public_key=1
    registry_file=1
    chains_directory=1
    legacy_start_script=0
    legacy_configure_script=0
    legacy_common_script=0
    version_json={version_json}
    "
        );

        let inspection = parse_inspection_output(&output).unwrap();

        // Нет start.py, поэтому полноценный ModernCli
        // обнаружен быть не должен.
        assert_eq!(inspection.layout_kind(), HopperLayoutKind::Unknown);

        assert!(!inspection.looks_like_hopper());
    }

    #[test]
    fn reports_invalid_version_json() {
        let output = "\
    os=Linux
    arch=x86_64
    version_json={this-is-not-json}
    ";

        let result = parse_inspection_output(output);

        assert!(matches!(
            result,
            Err(HopperInspectionError::InvalidVersionJson(_))
        ));
    }
}
