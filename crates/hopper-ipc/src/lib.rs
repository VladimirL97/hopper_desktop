use hopper_core::{ServerProfile, TunnelState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const IPC_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
    GetStatus,
    ListServers,
    AddServer(ServerProfile),
    Connect { chain_id: Uuid },
    Disconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Status(ServiceStatus),
    Servers(Vec<ServerProfile>),
    Accepted,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub protocol_version: u16,
    pub tunnel_state: TunnelState,
}

impl Default for ServiceStatus {
    fn default() -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            tunnel_state: TunnelState::Disconnected,
        }
    }
}
