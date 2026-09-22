use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::{
            ClientProtocolUpgrader, ServerProtocolAdmission, ServerProtocolUpgrade,
            ServerProtocolUpgrader,
        },
        transport::ConnectedTransport,
    },
    socket::udp::UdpSession,
    tunnel::Tunnel,
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    socket::tcp::RuntimeTcpSocket,
    tunnel::wireguard::{WgConfig, WgRole, upgrade_accepted, upgrade_connected, url_options},
};

use super::{ClientAdapter, ServerAdapter};

/// Serves one connection role: the client adapter dials with the dialer half
/// of the derived keys, the server adapter accepts with the listener half
/// (see [`WgRole`]). Both keep a legacy config for the `#legacy-keys=1`
/// opt-in.
struct WireGuardAdapter {
    config: WgConfig,
    legacy_config: WgConfig,
}

impl WireGuardAdapter {
    fn new(global_ctx: &ArcGlobalCtx, role: WgRole) -> Self {
        let identity = global_ctx.get_network_identity();
        let network_secret = identity.network_secret.unwrap_or_default();
        Self {
            config: WgConfig::new_from_network_identity(
                &identity.network_name,
                &network_secret,
                role,
            ),
            legacy_config: WgConfig::new_legacy_from_network_identity(
                &identity.network_name,
                &network_secret,
            ),
        }
    }

    /// Picks the derivation for one link from the url fragment:
    /// `#legacy-keys=1` opts into the retired SipHash keys for peers that
    /// have not upgraded; the default is the argon2id derivation.
    fn config_for(&self, url: &url::Url) -> anyhow::Result<WgConfig> {
        Ok(if url_options(url)?.legacy_keys {
            self.legacy_config.clone()
        } else {
            self.config.clone()
        })
    }
}

pub(super) fn client_adapter(global_ctx: &ArcGlobalCtx) -> ClientAdapter {
    Arc::new(WireGuardAdapter::new(global_ctx, WgRole::Dialer))
}

pub(super) fn server_adapter(global_ctx: &ArcGlobalCtx) -> ServerAdapter {
    Arc::new(WireGuardAdapter::new(global_ctx, WgRole::Listener))
}

#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for WireGuardAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "wg"
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::Udp(session) = connected else {
            anyhow::bail!("WireGuard protocol requires a UDP session");
        };
        let config = self.config_for(&requested_url)?;
        Ok(upgrade_connected(session, requested_url, config).await?)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for WireGuardAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "wg"
    }

    async fn upgrade_tcp(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("unsupported native TCP server protocol upgrader: wg")
    }

    async fn upgrade_udp(
        &self,
        session: UdpSession,
        local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        let config = self.config_for(&local_url)?;
        Ok(ServerProtocolUpgrade::Tunnel(upgrade_accepted(
            session, config,
        )?))
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("unsupported native byte-stream server protocol upgrader: wg")
    }
}
