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

/// Реальная роль hop-а на стороне Hopper.
///
/// Важно:
/// - первый сервер многосерверной цепочки является Entry для UI,
///   но на сервере Hopper он работает как `relay`;
/// - только последний сервер цепочки работает как `exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopRole {
    /// Промежуточный узел, передающий трафик дальше.
    Relay,

    /// Последний узел цепочки, выпускающий трафик в интернет.
    Exit,
}

/// Один заранее рассчитанный hop внутри каскада.
///
/// Здесь пока нет SSH-паролей, tunnel ports и overlay IP.
/// Это только структурный план цепочки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedHop {
    /// Сервер из нашей Server Library.
    pub server_id: ServerId,

    /// Позиция сервера в цепочке.
    ///
    /// 0 = первый сервер, к которому подключается клиент.
    pub index: usize,

    /// Серверная роль Hopper.
    pub role: HopRole,

    /// Предыдущий сервер в направлении к клиенту.
    ///
    /// Для index=0 upstream отсутствует.
    pub upstream: Option<ServerId>,

    /// Следующий сервер в направлении к exit.
    ///
    /// Для последнего hop downstream отсутствует.
    pub downstream: Option<ServerId>,
}

/// Рассчитанный план Hopper-цепочки.
///
/// HopChain хранит пользовательский порядок серверов.
/// ChainPlan превращает этот порядок в реальные роли
/// и связи между соседними узлами.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainPlan {
    /// Один и тот же chain_id используется на всех hops.
    pub chain_id: ChainId,

    /// Hops идут в направлении:
    ///
    /// Desktop -> Entry -> Relay -> ... -> Exit.
    pub hops: Vec<PlannedHop>,
}

impl ChainPlan {
    /// Строит структурный план из HopChain.
    ///
    /// Пример для трёх серверов:
    ///
    /// index 0 -> relay
    /// index 1 -> relay
    /// index 2 -> exit
    ///
    /// Для одного сервера:
    ///
    /// index 0 -> exit
    pub fn from_chain(chain: &HopChain) -> Self {
        // HopChain::new() не разрешает пустую цепочку.
        let last_index = chain.servers.len() - 1;

        let hops = chain
            .servers
            .iter()
            .enumerate()
            .map(|(index, server_id)| {
                // Только последний сервер является exit.
                // Все предыдущие серверы работают как relay.
                let role = if index == last_index {
                    HopRole::Exit
                } else {
                    HopRole::Relay
                };

                // Upstream — предыдущий сервер в цепочке.
                //
                // Для самого первого hop его нет,
                // потому что перед ним находится desktop-клиент.
                let upstream = if index == 0 {
                    None
                } else {
                    Some(chain.servers[index - 1])
                };

                // Downstream — следующий сервер в сторону exit.
                //
                // У exit downstream отсутствует.
                let downstream = if index == last_index {
                    None
                } else {
                    Some(chain.servers[index + 1])
                };

                PlannedHop {
                    server_id: *server_id,
                    index,
                    role,
                    upstream,
                    downstream,
                }
            })
            .collect();

        Self {
            chain_id: chain.id,
            hops,
        }
    }

    /// Первый hop.
    ///
    /// Именно к нему позже будет подключаться desktop-клиент.
    pub fn entry(&self) -> &PlannedHop {
        self.hops
            .first()
            .expect("ChainPlan always contains at least one hop")
    }

    /// Последний hop.
    ///
    /// Он всегда имеет Hopper role=exit.
    pub fn exit(&self) -> &PlannedHop {
        self.hops
            .last()
            .expect("ChainPlan always contains at least one hop")
    }

    /// Порядок provisioning серверов.
    ///
    /// Hopper должен подготавливаться от конца цепочки к началу:
    ///
    /// Exit -> Relay -> ... -> Entry.
    pub fn provisioning_order(&self) -> impl DoubleEndedIterator<Item = &PlannedHop> {
        self.hops.iter().rev()
    }
}

/// Локальная библиотека серверов и цепочек.
///
/// Это аналог Server Library + Chains из мобильного Hopper.
///
/// Сервер хранится только один раз.
/// Цепочки содержат только ServerId в нужном порядке.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HopperLibrary {
    /// Все сохранённые Hopper-серверы.
    pub servers: Vec<ServerProfile>,

    /// Все созданные пользователем цепочки.
    pub chains: Vec<HopChain>,

    /// Цепочка, выбранная сейчас на Home screen.
    ///
    /// Это ещё НЕ означает, что VPN подключён.
    pub selected_chain_id: Option<ChainId>,
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

impl HopperLibrary {
    /// Создаёт пустую библиотеку.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет сервер в общую Server Library.
    ///
    /// Один ServerId не должен встречаться дважды.
    pub fn add_server(&mut self, server: ServerProfile) -> Result<(), LibraryError> {
        if self.servers.iter().any(|existing| existing.id == server.id) {
            return Err(LibraryError::DuplicateServer);
        }

        self.servers.push(server);

        Ok(())
    }

    /// Возвращает сервер по ServerId.
    pub fn server(&self, server_id: ServerId) -> Option<&ServerProfile> {
        self.servers.iter().find(|server| server.id == server_id)
    }

    /// Добавляет новую цепочку.
    ///
    /// Каждый ServerId внутри неё уже должен существовать
    /// в Server Library.
    ///
    /// При этом один сервер МОЖЕТ использоваться
    /// в нескольких разных цепочках.
    pub fn add_chain(&mut self, chain: HopChain) -> Result<(), LibraryError> {
        if self.chains.iter().any(|existing| existing.id == chain.id) {
            return Err(LibraryError::DuplicateChain);
        }

        for server_id in &chain.servers {
            if self.server(*server_id).is_none() {
                return Err(LibraryError::UnknownServer);
            }
        }

        self.chains.push(chain);

        Ok(())
    }

    /// Получает цепочку по ChainId.
    pub fn chain(&self, chain_id: ChainId) -> Option<&HopChain> {
        self.chains.iter().find(|chain| chain.id == chain_id)
    }

    /// Выбирает цепочку для следующего VPN-подключения.
    ///
    /// Здесь VPN пока не запускается.
    /// Это только выбор пользователя.
    pub fn select_chain(&mut self, chain_id: ChainId) -> Result<(), LibraryError> {
        if self.chain(chain_id).is_none() {
            return Err(LibraryError::UnknownChain);
        }

        self.selected_chain_id = Some(chain_id);

        Ok(())
    }

    /// Возвращает выбранную цепочку.
    pub fn selected_chain(&self) -> Option<&HopChain> {
        let chain_id = self.selected_chain_id?;

        self.chain(chain_id)
    }

    /// Удаляет цепочку.
    ///
    /// Серверы при этом НЕ удаляются из Server Library,
    /// потому что они могут использоваться другими цепочками.
    pub fn remove_chain(&mut self, chain_id: ChainId) -> Result<(), LibraryError> {
        let position = self
            .chains
            .iter()
            .position(|chain| chain.id == chain_id)
            .ok_or(LibraryError::UnknownChain)?;

        self.chains.remove(position);

        // Если удалили выбранную цепочку,
        // Home больше не должен указывать на неё.
        if self.selected_chain_id == Some(chain_id) {
            self.selected_chain_id = None;
        }

        Ok(())
    }

    /// Удаляет сервер из Server Library.
    ///
    /// Нельзя удалить сервер, пока хотя бы одна chain
    /// всё ещё содержит ссылку на него.
    pub fn remove_server(&mut self, server_id: ServerId) -> Result<(), LibraryError> {
        let is_used = self
            .chains
            .iter()
            .any(|chain| chain.servers.contains(&server_id));

        if is_used {
            return Err(LibraryError::ServerInUse);
        }

        let position = self
            .servers
            .iter()
            .position(|server| server.id == server_id)
            .ok_or(LibraryError::UnknownServer)?;

        self.servers.remove(position);

        Ok(())
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LibraryError {
    #[error("server already exists in the library")]
    DuplicateServer,

    #[error("chain already exists in the library")]
    DuplicateChain,

    #[error("chain references unknown server")]
    UnknownServer,

    #[error("unknown chain")]
    UnknownChain,

    #[error("server is still used by one or more chains")]
    ServerInUse,
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

    #[test]
    fn builds_single_hop_chain_plan() {
        let server = ServerId::new();

        let chain = HopChain::new("Single hop", vec![server]).unwrap();

        let plan = ChainPlan::from_chain(&chain);

        // Один сервер одновременно является entry и exit
        // с точки зрения пользовательской цепочки.
        assert_eq!(plan.hops.len(), 1);

        // Но серверная роль Hopper для единственного hop — exit.
        assert_eq!(plan.hops[0].role, HopRole::Exit);

        assert_eq!(plan.hops[0].index, 0);
        assert_eq!(plan.hops[0].server_id, server);

        // Соседних серверов нет.
        assert_eq!(plan.hops[0].upstream, None);
        assert_eq!(plan.hops[0].downstream, None);

        assert_eq!(plan.entry(), plan.exit());
    }

    #[test]
    fn builds_three_hop_chain_plan() {
        let server_a = ServerId::new();
        let server_b = ServerId::new();
        let server_c = ServerId::new();

        let chain = HopChain::new("Three hop cascade", vec![server_a, server_b, server_c]).unwrap();

        let plan = ChainPlan::from_chain(&chain);

        assert_eq!(plan.hops.len(), 3);

        // ---------------------------------------------------------
        // Первый сервер.
        //
        // Для UI это Entry.
        // Для Hopper server-side это relay.
        // ---------------------------------------------------------

        assert_eq!(plan.hops[0].server_id, server_a);
        assert_eq!(plan.hops[0].index, 0);
        assert_eq!(plan.hops[0].role, HopRole::Relay);

        assert_eq!(plan.hops[0].upstream, None);
        assert_eq!(plan.hops[0].downstream, Some(server_b));

        // ---------------------------------------------------------
        // Средний сервер — обычный relay.
        // ---------------------------------------------------------

        assert_eq!(plan.hops[1].server_id, server_b);
        assert_eq!(plan.hops[1].index, 1);
        assert_eq!(plan.hops[1].role, HopRole::Relay);

        assert_eq!(plan.hops[1].upstream, Some(server_a));

        assert_eq!(plan.hops[1].downstream, Some(server_c));

        // ---------------------------------------------------------
        // Последний сервер — exit.
        // ---------------------------------------------------------

        assert_eq!(plan.hops[2].server_id, server_c);
        assert_eq!(plan.hops[2].index, 2);
        assert_eq!(plan.hops[2].role, HopRole::Exit);

        assert_eq!(plan.hops[2].upstream, Some(server_b));

        assert_eq!(plan.hops[2].downstream, None);
    }

    #[test]
    fn chain_plan_provisions_exit_to_entry() {
        let server_a = ServerId::new();
        let server_b = ServerId::new();
        let server_c = ServerId::new();

        let chain = HopChain::new("Three hop cascade", vec![server_a, server_b, server_c]).unwrap();

        let plan = ChainPlan::from_chain(&chain);

        let order: Vec<ServerId> = plan.provisioning_order().map(|hop| hop.server_id).collect();

        // Provisioning идёт в направлении:
        //
        // Exit -> Relay -> Entry.
        assert_eq!(order, vec![server_c, server_b, server_a,]);
    }

    #[test]
    fn same_servers_can_be_used_in_multiple_chains() {
        let server_a = ServerProfile::new("Server A", "10.0.0.1", 22, "root").unwrap();

        let server_b = ServerProfile::new("Server B", "10.0.0.2", 22, "root").unwrap();

        let a_id = server_a.id;
        let b_id = server_b.id;

        let mut library = HopperLibrary::new();

        library.add_server(server_a).unwrap();
        library.add_server(server_b).unwrap();

        // Chain A -> B.
        let chain_ab = HopChain::new("A -> B", vec![a_id, b_id]).unwrap();

        // Chain B -> A.
        //
        // Используются ТЕ ЖЕ ServerId,
        // но порядок совершенно другой.
        let chain_ba = HopChain::new("B -> A", vec![b_id, a_id]).unwrap();

        library.add_chain(chain_ab).unwrap();
        library.add_chain(chain_ba).unwrap();

        assert_eq!(library.servers.len(), 2);
        assert_eq!(library.chains.len(), 2);

        assert_eq!(library.chains[0].servers, vec![a_id, b_id],);

        assert_eq!(library.chains[1].servers, vec![b_id, a_id],);
    }

    #[test]
    fn selects_chain_for_connection() {
        let server = ServerProfile::new("Server", "10.0.0.1", 22, "root").unwrap();

        let server_id = server.id;

        let mut library = HopperLibrary::new();

        library.add_server(server).unwrap();

        let chain = HopChain::new("My VPN", vec![server_id]).unwrap();

        let chain_id = chain.id;

        library.add_chain(chain).unwrap();

        assert!(library.selected_chain().is_none());

        library.select_chain(chain_id).unwrap();

        let selected = library.selected_chain().unwrap();

        assert_eq!(selected.id, chain_id);
        assert_eq!(selected.name, "My VPN");
    }
}
