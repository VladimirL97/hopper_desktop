# Architecture

## Principle

The UI must never own the tunnel. It communicates with a long-running system
service through a versioned IPC protocol.

```text
hopper-ui / future CLI
          |
          | versioned local IPC
          v
hopper-service
          |
          +-- shared Rust core
          +-- SSH / Hopper protocol (next milestones)
          +-- platform network backend
                 +-- Windows first
                 +-- macOS later
                 +-- Linux later
```

## Why this boundary

- UI can be replaced without redesigning the tunnel engine.
- Closing or crashing the UI does not have to tear down the VPN.
- Privileged networking remains isolated from the desktop UI.
- The same service API can later be used by a CLI and automated tests.

## First Windows milestones

1. Versioned local IPC.
2. Local configuration/storage model.
3. Manual existing-server form and validation.
4. SSH compatibility with the existing Hopper server.
5. Hopper framing/protocol compatibility tests.
6. Windows virtual adapter and routes.
7. DNS/IPv6 leak prevention and kill switch.
8. Multi-hop provisioning and tunnel.
9. Windows service installation.
10. Signed standalone installer.
