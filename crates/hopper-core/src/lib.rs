use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerProfile {
    pub id: ServerId,
    pub name: String,
    pub host: String,
    pub port: u16,
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

        Ok(Self {
            id: ServerId::new(),
            name,
            host,
            port,
            user,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TunnelState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

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
        assert_eq!(result.unwrap_err(), CoreError::InvalidServer("host is empty"));
    }
}
