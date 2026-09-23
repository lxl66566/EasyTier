use easytier_proto::api::{
    instance::{PeerInfo, list_peer_route_pair},
    manage::{MyNodeInfo, NetworkInstanceRunningInfo},
};

use crate::{
    config::toml::ConfigLoader as _,
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState},
};

/// Builds the process-level running snapshot directly from one core Instance.
#[allow(deprecated)]
pub async fn network_instance_running_info<H>(
    instance: &CoreInstance<H>,
) -> anyhow::Result<NetworkInstanceRunningInfo>
where
    H: CoreInstanceHost,
{
    let running = instance_running(instance);
    if !instance.is_ready() {
        return Ok(degraded_network_instance_info(
            running,
            instance.latest_error(),
        ));
    }

    let peers = instance
        .peer_snapshots()
        .await
        .into_iter()
        .map(|snapshot| PeerInfo {
            peer_id: snapshot.peer_id,
            default_conn_id: snapshot.default_conn_id.map(Into::into),
            directly_connected_conns: snapshot
                .directly_connected_conns
                .into_iter()
                .map(Into::into)
                .collect(),
            conns: snapshot.conns.into_iter().map(Into::into).collect(),
        })
        .collect::<Vec<_>>();
    let node = instance.node_snapshot().await;
    let routes = instance
        .route_snapshots()
        .await
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    let peer_route_pairs = list_peer_route_pair(peers.clone(), routes.clone());
    let dev_name = instance
        .toml_config()
        .map(|config| config.get_flags().dev_name)
        .unwrap_or_default();

    Ok(NetworkInstanceRunningInfo {
        dev_name,
        my_node_info: Some(MyNodeInfo {
            virtual_ipv4: node.ipv4_addr.map(Into::into),
            hostname: node.hostname,
            version: node.version,
            ips: Some(node.ip_list),
            stun_info: Some(node.stun_info),
            listeners: node.listeners.into_iter().map(Into::into).collect(),
            // Client private keys are returned only by the explicit portal RPC.
            vpn_portal_cfg: None,
            peer_id: node.peer_id,
        }),
        events: instance.management_events(),
        routes,
        peers,
        peer_route_pairs,
        running,
        error_msg: instance.latest_error(),
        foreign_network_summary: Some(instance.foreign_network_route_summary().await),
    })
}

/// Never-failing variant for list collectors: a failing instance yields a
/// degraded entry instead of aborting the whole list.
pub async fn network_instance_running_info_lossy<H>(
    instance: &CoreInstance<H>,
) -> NetworkInstanceRunningInfo
where
    H: CoreInstanceHost,
{
    match network_instance_running_info(instance).await {
        Ok(info) => info,
        Err(error) => {
            let instance_id = instance.instance_id();
            tracing::warn!(%instance_id, %error, "failed to collect network instance info");
            degraded_network_instance_info(instance_running(instance), Some(format!("{error:#}")))
        }
    }
}

fn instance_running<H>(instance: &CoreInstance<H>) -> bool
where
    H: CoreInstanceHost,
{
    !matches!(
        instance.state(),
        CoreInstanceState::Created | CoreInstanceState::Stopped
    )
}

fn degraded_network_instance_info(
    running: bool,
    error_msg: Option<String>,
) -> NetworkInstanceRunningInfo {
    NetworkInstanceRunningInfo {
        running,
        error_msg,
        ..Default::default()
    }
}
