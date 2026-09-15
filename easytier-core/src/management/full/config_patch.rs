use std::{fmt::Debug, sync::Arc};

use anyhow::Context as _;
use easytier_proto::api::config::{
    self, AclPatch, ConfigPatchAction, ExitNodePatch, InstanceConfigPatch, Patchable,
    PortForwardPatch, ProxyNetworkPatch, RoutePatch, UrlPatch, VpnPortalClientPatch,
};

use crate::{
    config::{
        api_input::managed_credential_from_proto,
        peers::AclRuleConfig,
        runtime::CoreInstanceRuntimeConfig,
        toml::{ConfigLoader as _, TomlConfig},
    },
    instance::{CoreInstance, CoreInstanceConfig, CoreInstanceHost, CoreInstanceState},
    peers::credential_manager::CredentialManager,
};

#[async_trait::async_trait]
pub trait ConfigPatchPersistence: Send + Sync {
    async fn persist(&self, instance_id: uuid::Uuid, config: &TomlConfig) -> anyhow::Result<()>;
}

#[cfg(test)]
thread_local! {
    /// Test-only observation hook: (full TOML serializations, full
    /// normalizations) performed by config patches on this thread. Guards
    /// the skip-untouched-sections behavior of [`PatchTransaction`].
    static PATCH_STATS_FOR_TEST: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
pub(crate) fn reset_patch_stats_for_test() {
    PATCH_STATS_FOR_TEST.with(|stats| stats.set((0, 0)));
}

#[cfg(test)]
pub(crate) fn patch_stats_for_test() -> (usize, usize) {
    PATCH_STATS_FOR_TEST.with(|stats| stats.get())
}

#[cfg(test)]
fn record_patch_stats(serializations: usize, normalizations: usize) {
    PATCH_STATS_FOR_TEST.with(|stats| {
        let (serial, norm) = stats.get();
        stats.set((serial + serializations, norm + normalizations));
    });
}

#[cfg(not(test))]
fn record_patch_stats(_serializations: usize, _normalizations: usize) {}

/// Coalesces the per-section candidate mutations of one patch request.
///
/// The candidate starts as an exact copy of the shared config and is only
/// mutated by the section helpers below, each reporting whether it touched
/// the candidate so [`Self::mark_dirty`] can be set. While the candidate is
/// clean (nothing touched it since the last commit), validation, persistence,
/// and TOML serialization are skipped entirely, and the normalized form of
/// the last commit is reused instead of re-normalizing.
///
/// This relies on the shared config being immutable while an instance
/// operation lock is held: every live-config writer mutates it through this
/// module under that lock.
struct PatchTransaction<'a, H: CoreInstanceHost> {
    instance: &'a CoreInstance<H>,
    shared: &'a TomlConfig,
    candidate: TomlConfig,
    /// The candidate may differ from `shared` since the last commit.
    dirty: bool,
    /// Normalized form of the current `shared` content from the last
    /// successful commit validation; reused while both stay in sync.
    normalized: Option<CoreInstanceConfig>,
}

impl<'a, H: CoreInstanceHost> PatchTransaction<'a, H> {
    fn new(instance: &'a CoreInstance<H>, shared: &'a TomlConfig) -> Self {
        Self {
            instance,
            shared,
            candidate: shared.detached_snapshot(),
            dirty: false,
            normalized: None,
        }
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// True when the candidate serializes differently from the shared config.
    fn content_changed(&self) -> bool {
        let changed = self.shared.dump() != self.candidate.dump();
        record_patch_stats(2, 0);
        changed
    }

    /// Validates the candidate, durably persists it when its serialized form
    /// changed, and mirrors it into the shared config. Skipped entirely while
    /// the candidate is clean.
    async fn commit(
        &mut self,
        persistence: Option<&dyn ConfigPatchPersistence>,
    ) -> anyhow::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let normalized = validate_candidate(self.instance, &self.candidate)?;
        if self.content_changed() {
            if let Some(persistence) = persistence {
                persistence
                    .persist(self.instance.instance_id(), &self.candidate)
                    .await?;
            }
            self.shared.replace_from_snapshot(&self.candidate);
        }
        self.dirty = false;
        self.normalized = Some(normalized);
        Ok(())
    }

    /// Validates and durably persists the candidate WITHOUT mirroring it into
    /// the shared config. Used by the VPN portal section, which may only
    /// replace the shared state after the live portal accepted the update;
    /// the caller then records that replace via [`Self::note_replaced`].
    async fn validate_and_persist(
        &mut self,
        persistence: Option<&dyn ConfigPatchPersistence>,
    ) -> anyhow::Result<CoreInstanceConfig> {
        let normalized = validate_candidate(self.instance, &self.candidate)?;
        if self.dirty
            && self.content_changed()
            && let Some(persistence) = persistence
        {
            persistence
                .persist(self.instance.instance_id(), &self.candidate)
                .await?;
        }
        Ok(normalized)
    }

    /// Records that the caller mirrored the candidate into the shared config
    /// after a successful hot apply.
    fn note_replaced(&mut self, normalized: CoreInstanceConfig) {
        self.dirty = false;
        self.normalized = Some(normalized);
    }

    /// Normalized form of the committed config. Reuses the last commit's
    /// result while the candidate is clean; validates lazily (and then caches)
    /// when no commit happened in this request.
    fn normalized_config(&mut self) -> anyhow::Result<CoreInstanceConfig> {
        if !self.dirty
            && let Some(normalized) = &self.normalized
        {
            return Ok(normalized.clone());
        }
        let normalized = validate_candidate(self.instance, &self.candidate)?;
        if !self.dirty {
            // Clean means the candidate still equals the shared config, so
            // the result doubles as the shared normalized form.
            self.normalized = Some(normalized.clone());
        }
        Ok(normalized)
    }

    /// Runtime config for the trailing runtime re-sync, reusing the last
    /// commit's normalized form when available.
    fn shared_runtime_config(&self) -> anyhow::Result<CoreInstanceRuntimeConfig> {
        match &self.normalized {
            Some(normalized) => Ok(runtime_config_from_normalized(normalized)),
            None => runtime_config_from_toml(self.instance, self.shared),
        }
    }
}

pub async fn apply_config_patch<H>(
    instance: &Arc<CoreInstance<H>>,
    patch: InstanceConfigPatch,
    persistence: Option<&dyn ConfigPatchPersistence>,
) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    let _operation = instance.operation.lock().await;
    if instance.state() != CoreInstanceState::Running {
        anyhow::bail!("instance is not ready; config patch rejected");
    }

    let config = instance
        .toml_config()
        .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
    let parsed_prefix =
        parse_ipv6_public_addr_prefix_patch(patch.ipv6_public_addr_prefix.as_deref())?;
    // Take the credential set out first so the host-facing copy below never
    // clones secret material.
    let mut patch = patch;
    let managed_credentials = patch.managed_credentials.take();
    let patch_for_host = patch_without_managed_credentials(&patch);

    let mut tx = PatchTransaction::new(instance, &config);

    // Preserve the existing ordered partial-commit contract: earlier valid
    // sub-patches remain applied if a later sub-patch fails.
    let patch_result: anyhow::Result<(bool, bool)> = async {
        if patch_port_forwards(&tx.candidate, patch.port_forwards) {
            tx.mark_dirty();
        }
        tx.commit(persistence).await?;

        if patch_acl(&tx.candidate, patch.acl)? {
            tx.mark_dirty();
        }
        tx.commit(persistence).await?;

        if patch_proxy_networks(&tx.candidate, patch.proxy_networks)? {
            tx.mark_dirty();
        }
        tx.commit(persistence).await?;

        if patch_routes(&tx.candidate, patch.routes) {
            tx.mark_dirty();
        }
        tx.commit(persistence).await?;

        if patch_exit_nodes_config(&tx.candidate, patch.exit_nodes) {
            tx.mark_dirty();
        }
        tx.commit(persistence).await?;
        instance
            .update_exit_nodes(tx.normalized_config()?.peer.exit_nodes.clone())
            .await;

        if patch_mapped_listeners(&tx.candidate, patch.mapped_listeners) {
            tx.mark_dirty();
        }
        tx.commit(persistence).await?;

        patch_connectors(instance, patch.connectors)?;

        let mut provider_config_changed = false;
        if let Some(hostname) = patch.hostname {
            tx.candidate.set_hostname(Some(hostname));
            tx.mark_dirty();
        }
        if let Some(ipv4) = patch.ipv4
            && !tx.candidate.get_dhcp()
        {
            tx.candidate.set_ipv4(Some(ipv4.into()));
            tx.mark_dirty();
        }
        if let Some(ipv6) = patch.ipv6 {
            tx.candidate.set_ipv6(Some(ipv6.into()));
            tx.mark_dirty();
        }
        if let Some(disable_relay_data) = patch.disable_relay_data {
            let mut flags = tx.candidate.get_flags();
            flags.disable_relay_data = disable_relay_data;
            tx.candidate.set_flags(flags);
            tx.mark_dirty();
        }
        if let Some(prefer_peer_relay) = patch.prefer_peer_relay {
            let mut flags = tx.candidate.get_flags();
            flags.prefer_peer_relay = prefer_peer_relay;
            tx.candidate.set_flags(flags);
            tx.mark_dirty();
        }
        if let Some(enabled) = patch.ipv6_public_addr_provider {
            tx.candidate.set_ipv6_public_addr_provider(enabled);
            tx.mark_dirty();
            provider_config_changed = true;
        }
        if let Some(enabled) = patch.ipv6_public_addr_auto {
            tx.candidate.set_ipv6_public_addr_auto(enabled);
            tx.mark_dirty();
        }
        if let Some(prefix) = parsed_prefix {
            tx.candidate.set_ipv6_public_addr_prefix(prefix);
            tx.mark_dirty();
            provider_config_changed = true;
        }
        let mut managed_credentials_changed = false;

        // Runs last so client validation sees the fully patched candidate,
        // including routes and the node IPv4 set earlier in this request.
        if !patch.vpn_portal_clients.is_empty() {
            let previous = config.detached_snapshot();
            apply_vpn_portal_client_patches(&tx.candidate, patch.vpn_portal_clients)?;
            tx.mark_dirty();
            // Deep-validate and durably persist before hot-applying. A failed
            // write leaves the live Portal untouched. If the host rejects the
            // hot update, restore the previous durable snapshot before
            // returning so a later patch cannot overwrite from stale shared
            // state and a restart cannot apply a rejected client set.
            let normalized = tx.validate_and_persist(persistence).await?;
            #[cfg(feature = "vpn-portal")]
            {
                let portal = normalized
                    .vpn_portal
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("VPN portal is not configured"))?;
                if let Err(error) = instance
                    .update_vpn_portal_clients(
                        portal.clients,
                        &runtime_config_from_normalized(&normalized),
                    )
                    .await
                {
                    if let Some(persistence) = persistence
                        && let Err(rollback_error) =
                            persistence.persist(instance.instance_id(), &previous).await
                    {
                        return Err(error.context(format!(
                            "failed to restore durable configuration after VPN portal update: \
                             {rollback_error:#}"
                        )));
                    }
                    return Err(error);
                }
            }
            #[cfg(not(feature = "vpn-portal"))]
            {
                let _ = &normalized;
            }
            config.replace_from_snapshot(&tx.candidate);
            tx.note_replaced(normalized);
        }

        if let Some(managed) = &managed_credentials {
            // Managed credential patch transaction: validate and reserve →
            // persist → install. The reservation prevents base or ephemeral
            // credential mutations from invalidating the replacement while
            // the durable write is in flight, without holding a synchronous
            // lock across the await. Dropping the replacement before install
            // releases the reservation.
            //
            // Accepted consistency limits:
            //
            // 1. A persistence implementation may finish its write after this
            //    RPC future is cancelled. The reservation is then released and
            //    the running instance keeps its previous credentials even if
            //    the durable file contains the replacement. A retry, controller
            //    reconcile, or restart is required to converge; until then a
            //    removed credential may remain trusted by the running instance.
            //
            // 2. This instance operation is not serialized with a process-level
            //    instance overwrite. The built-in web reconciler serializes its
            //    own actions, but independently concurrent admin RPCs are
            //    last-writer-wins and may leave the running instance and durable
            //    file on different config generations. A restart aligns runtime
            //    with the file; controller reconcile is required to restore its
            //    desired generation.
            let credential_manager = instance.credential_manager();
            let entries = managed
                .entries
                .iter()
                .map(managed_credential_from_proto)
                .collect::<Vec<_>>();
            let replacement = credential_manager
                .validate_managed_credentials(&entries)
                .map_err(anyhow::Error::msg)?;
            tx.candidate.set_managed_credentials(entries);
            tx.mark_dirty();
            // Commit persists before installing secret authority so a
            // successful replacement survives restart.
            tx.commit(persistence).await?;
            managed_credentials_changed =
                CredentialManager::install_managed_credentials(replacement);
        } else {
            tx.commit(persistence).await?;
        }
        let runtime = runtime_config_from_normalized(&tx.normalized_config()?);
        if patch_for_host != InstanceConfigPatch::default() {
            instance
                .instance_runtime
                .synchronize_config(&patch_for_host, &runtime);
        }
        Ok((provider_config_changed, managed_credentials_changed))
    }
    .await;

    // Re-sync the running instance with everything durably committed above,
    // even when the patch failed part-way (partial-commit contract). When the
    // patch already failed, the re-sync is best-effort: its own failure (e.g.
    // the instance moved to Stopping mid-request) must not mask the patch
    // error the caller needs.
    let runtime_sync = match tx.shared_runtime_config() {
        Ok(runtime) => {
            instance
                .update_runtime_config_under_operation(runtime)
                .await
        }
        Err(error) => Err(error),
    };
    let (provider_config_changed, managed_credentials_changed) = match (patch_result, runtime_sync)
    {
        (Ok(flags), Ok(())) => flags,
        (Ok(_), Err(error)) => return Err(error),
        (Err(patch_error), Ok(())) => return Err(patch_error),
        (Err(patch_error), Err(runtime_error)) => {
            tracing::warn!(
                %runtime_error,
                "runtime config re-sync failed after a failed config patch; reporting the patch error"
            );
            return Err(patch_error);
        }
    };
    if patch_for_host != InstanceConfigPatch::default() {
        instance
            .instance_runtime
            .publish_config_patch(patch_for_host);
    }
    if managed_credentials_changed {
        instance.notify_credential_changed();
    }
    #[cfg(feature = "public-ipv6-provider")]
    if provider_config_changed && instance.state() == CoreInstanceState::Running {
        instance.reconcile_public_ipv6_provider().await;
    }
    #[cfg(not(feature = "public-ipv6-provider"))]
    let _ = provider_config_changed;
    Ok(())
}

fn patch_without_managed_credentials(patch: &InstanceConfigPatch) -> InstanceConfigPatch {
    let mut patch = patch.clone();
    patch.managed_credentials = None;
    patch
}

fn validate_candidate<H>(
    instance: &CoreInstance<H>,
    candidate: &TomlConfig,
) -> anyhow::Result<CoreInstanceConfig>
where
    H: CoreInstanceHost,
{
    record_patch_stats(0, 1);
    let normalized = CoreInstanceConfig::from_toml_with_host(candidate, instance.host_config())?;
    let runtime = runtime_config_from_normalized(&normalized);
    runtime.services.public_ipv6_provider.validate()?;
    instance.validate_runtime_config_capabilities(&runtime)?;
    Ok(normalized)
}

fn runtime_config_from_toml<H>(
    instance: &CoreInstance<H>,
    config: &TomlConfig,
) -> anyhow::Result<CoreInstanceRuntimeConfig>
where
    H: CoreInstanceHost,
{
    record_patch_stats(0, 1);
    let normalized = CoreInstanceConfig::from_toml_with_host(config, instance.host_config())?;
    Ok(runtime_config_from_normalized(&normalized))
}

fn runtime_config_from_normalized(config: &CoreInstanceConfig) -> CoreInstanceRuntimeConfig {
    CoreInstanceRuntimeConfig {
        services: config.connectivity.runtime.clone(),
        peer: Arc::new(config.peer.snapshot.clone()),
    }
}

fn parse_ipv6_public_addr_prefix_patch(
    prefix: Option<&str>,
) -> anyhow::Result<Option<Option<cidr::Ipv6Cidr>>> {
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Ok(Some(None));
    }
    Ok(Some(Some(prefix.parse().with_context(|| {
        format!("failed to parse ipv6 public address prefix: {prefix}")
    })?)))
}

fn trace_patchables<T: Debug>(patches: &[Patchable<T>]) {
    for patch in patches {
        match patch.action {
            Some(ConfigPatchAction::Add) | Some(ConfigPatchAction::Remove) => {
                if let Some(value) = &patch.value {
                    tracing::info!(?patch.action, ?value, "applying configuration patch");
                } else {
                    tracing::warn!(?patch.action, "ignored configuration patch without value");
                }
            }
            Some(ConfigPatchAction::Clear) => {
                tracing::info!("clearing configuration collection");
            }
            None => tracing::warn!("ignored invalid configuration patch action"),
        }
    }
}

#[cfg(test)]
mod managed_credential_tests {
    use easytier_proto::api::manage::ManagedCredentialSet;

    use super::*;

    #[test]
    fn event_patch_drops_managed_credential_secrets() {
        let patch = InstanceConfigPatch {
            managed_credentials: Some(ManagedCredentialSet::default()),
            ..Default::default()
        };

        assert!(
            patch_without_managed_credentials(&patch)
                .managed_credentials
                .is_none()
        );
    }
}

/// `patch_vec` appends blindly on Add, so a retried request whose response
/// was lost would add the same entry twice (e.g. a second identical
/// port-forward whose bind then fails). Drop duplicates after patching,
/// keeping the first occurrence.
fn patch_vec_idempotent<T: PartialEq + Clone>(current: &mut Vec<T>, patches: Vec<Patchable<T>>) {
    config::patch_vec(current, patches);
    let mut unique: Vec<T> = Vec::with_capacity(current.len());
    current.retain(|value| {
        if unique.contains(value) {
            false
        } else {
            unique.push(value.clone());
            true
        }
    });
}

/// Reports whether the call may have modified `config`.
fn patch_port_forwards(config: &TomlConfig, patches: Vec<PortForwardPatch>) -> bool {
    if patches.is_empty() {
        return false;
    }
    let mut current = config.get_port_forwards();
    let patches = patches
        .into_iter()
        .map(|patch| Patchable {
            action: ConfigPatchAction::try_from(patch.action).ok(),
            value: patch.cfg.map(Into::into),
        })
        .collect::<Vec<_>>();
    trace_patchables(&patches);
    patch_vec_idempotent(&mut current, patches);
    config.set_port_forwards(current);
    true
}

/// Reports whether the call may have modified `config`.
fn patch_acl(config: &TomlConfig, patch: Option<AclPatch>) -> anyhow::Result<bool> {
    let Some(patch) = patch else {
        return Ok(false);
    };
    let mut acl = AclRuleConfig {
        acl: config.get_acl(),
        tcp_whitelist: config.get_tcp_whitelist(),
        udp_whitelist: config.get_udp_whitelist(),
        whitelist_priority: None,
    };
    if let Some(next) = patch.acl {
        acl.acl = Some(next);
    }
    if !patch.tcp_whitelist.is_empty() {
        let patches = patch
            .tcp_whitelist
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        trace_patchables(&patches);
        patch_vec_idempotent(&mut acl.tcp_whitelist, patches);
    }
    if !patch.udp_whitelist.is_empty() {
        let patches = patch
            .udp_whitelist
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        trace_patchables(&patches);
        patch_vec_idempotent(&mut acl.udp_whitelist, patches);
    }
    acl.build()?;
    config.set_acl(acl.acl);
    config.set_tcp_whitelist(acl.tcp_whitelist);
    config.set_udp_whitelist(acl.udp_whitelist);
    Ok(true)
}

/// Reports whether the call may have modified `config`.
fn patch_proxy_networks(
    config: &TomlConfig,
    patches: Vec<ProxyNetworkPatch>,
) -> anyhow::Result<bool> {
    let changed = !patches.is_empty();
    // Two-phase: verify every add before touching the config so a failing
    // entry cannot leave a partially applied (and then committed) prefix.
    // The check mirrors the one in `TomlConfig::add_proxy_cidr`, which can no
    // longer be reached with invalid input afterwards.
    for patch in &patches {
        let Ok(ConfigPatchAction::Add) = ConfigPatchAction::try_from(patch.action) else {
            continue;
        };
        let (Some(cidr), Some(mapped_cidr)) = (
            patch.cidr.map(cidr::Ipv4Cidr::from),
            patch.mapped_cidr.map(cidr::Ipv4Cidr::from),
        ) else {
            continue;
        };
        if cidr.network_length() != mapped_cidr.network_length() {
            anyhow::bail!(
                "Mapped CIDR must have the same network length as the original CIDR: {} != {}",
                cidr.network_length(),
                mapped_cidr.network_length()
            );
        }
    }
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(cidr) = patch.cidr.map(Into::into) else {
                    tracing::warn!("ignored proxy-network add without CIDR");
                    continue;
                };
                config.add_proxy_cidr(cidr, patch.mapped_cidr.map(Into::into))?;
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(cidr) = patch.cidr.map(Into::into) else {
                    tracing::warn!("ignored proxy-network remove without CIDR");
                    continue;
                };
                config.remove_proxy_cidr(cidr);
            }
            Ok(ConfigPatchAction::Clear) => config.clear_proxy_cidrs(),
            Err(_) => tracing::warn!(
                action = patch.action,
                "ignored invalid proxy-network action"
            ),
        }
    }
    Ok(changed)
}

/// Reports whether the call may have modified `config`.
fn patch_routes(config: &TomlConfig, patches: Vec<RoutePatch>) -> bool {
    if patches.is_empty() {
        return false;
    }
    let mut current = config.get_routes().unwrap_or_default();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    patch_vec_idempotent(&mut current, patches);
    config.set_routes((!current.is_empty()).then_some(current));
    true
}

/// Reports whether the call may have modified `config`.
fn patch_exit_nodes_config(config: &TomlConfig, patches: Vec<ExitNodePatch>) -> bool {
    if patches.is_empty() {
        return false;
    }
    let mut current = config.get_exit_nodes();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    patch_vec_idempotent(&mut current, patches);
    config.set_exit_nodes(current);
    true
}

/// Reports whether the call may have modified `config`.
fn patch_mapped_listeners(config: &TomlConfig, patches: Vec<UrlPatch>) -> bool {
    if patches.is_empty() {
        return false;
    }
    let mut current = config.get_mapped_listeners();
    let patches = patches.into_iter().map(Into::into).collect::<Vec<_>>();
    trace_patchables(&patches);
    patch_vec_idempotent(&mut current, patches);
    config.set_mapped_listeners((!current.is_empty()).then_some(current));
    true
}

/// Applies VPN portal client patches to the candidate TOML model. The live
/// portal is updated by the caller after the candidate commits, so deep
/// validation runs against the final configuration state.
fn apply_vpn_portal_client_patches(
    config: &TomlConfig,
    patches: Vec<VpnPortalClientPatch>,
) -> anyhow::Result<()> {
    if patches.is_empty() {
        return Ok(());
    }
    let mut portal = config
        .get_vpn_portal_config()
        .ok_or_else(|| anyhow::anyhow!("VPN portal is not configured; cannot patch its clients"))?;
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(client) = patch.client else {
                    tracing::warn!("ignored VPN portal client add without client");
                    continue;
                };
                let virtual_ip =
                    client
                        .virtual_ip
                        .parse::<cidr::Ipv4Inet>()
                        .with_context(|| {
                            format!(
                                "invalid VPN portal client virtual CIDR: {}",
                                client.virtual_ip
                            )
                        })?;
                portal
                    .clients
                    .push(crate::config::toml::VpnPortalClientConfig {
                        name: client.name,
                        virtual_ip,
                        groups: client.groups,
                    });
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(client) = patch.client else {
                    tracing::warn!("ignored VPN portal client remove without client");
                    continue;
                };
                let before = portal.clients.len();
                portal
                    .clients
                    .retain(|existing| existing.name != client.name);
                if portal.clients.len() == before {
                    anyhow::bail!("VPN portal client not found: {}", client.name);
                }
            }
            Ok(ConfigPatchAction::Clear) => portal.clients.clear(),
            Err(_) => tracing::warn!(
                action = patch.action,
                "ignored invalid VPN portal client action"
            ),
        }
    }
    config.set_vpn_portal_config(portal);
    Ok(())
}

fn patch_connectors<H>(instance: &CoreInstance<H>, patches: Vec<UrlPatch>) -> anyhow::Result<()>
where
    H: CoreInstanceHost,
{
    for patch in patches {
        match ConfigPatchAction::try_from(patch.action) {
            Ok(ConfigPatchAction::Add) => {
                let Some(url) = patch.url.map(Into::<url::Url>::into) else {
                    tracing::warn!("ignored connector add without URL");
                    continue;
                };
                if !instance.host_config().accepts_runtime_url(&url) {
                    continue;
                }
                instance.add_connector(url)?;
            }
            Ok(ConfigPatchAction::Remove) => {
                let Some(url) = patch.url.map(Into::<url::Url>::into) else {
                    tracing::warn!("ignored connector remove without URL");
                    continue;
                };
                if !instance.host_config().accepts_runtime_url(&url) {
                    continue;
                }
                if !instance.remove_connector(&url) {
                    anyhow::bail!("connector not found: {url}");
                }
            }
            Ok(ConfigPatchAction::Clear) => instance.clear_connectors(),
            Err(_) => tracing::warn!(action = patch.action, "ignored invalid connector action"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml::{VpnPortalClientConfig, VpnPortalConfig};
    use easytier_proto::api::manage::VpnPortalClientConfig as ClientPb;
    use easytier_proto::common::{PortForwardConfigPb, SocketType};

    fn port_forward_add(bind_addr: &str, dst_addr: &str) -> PortForwardPatch {
        PortForwardPatch {
            action: ConfigPatchAction::Add as i32,
            cfg: Some(PortForwardConfigPb {
                bind_addr: Some(bind_addr.parse::<std::net::SocketAddr>().unwrap().into()),
                dst_addr: Some(dst_addr.parse::<std::net::SocketAddr>().unwrap().into()),
                socket_type: SocketType::Tcp as i32,
            }),
        }
    }

    fn proxy_add(cidr: &str, mapped_cidr: Option<&str>) -> ProxyNetworkPatch {
        ProxyNetworkPatch {
            action: ConfigPatchAction::Add as i32,
            cidr: Some(cidr.parse::<cidr::Ipv4Inet>().unwrap().into()),
            mapped_cidr: mapped_cidr.map(|cidr| cidr.parse::<cidr::Ipv4Inet>().unwrap().into()),
        }
    }

    #[test]
    fn port_forward_add_is_idempotent() {
        let config = TomlConfig::default();
        let forward = port_forward_add("127.0.0.1:18080", "10.144.144.2:8080");

        // A duplicate within one request and a retry after a lost response
        // must both end up as a single forward; the second bind would fail.
        assert!(patch_port_forwards(
            &config,
            vec![forward.clone(), forward.clone()]
        ));
        assert!(patch_port_forwards(&config, vec![forward]));
        assert_eq!(config.get_port_forwards().len(), 1);
    }

    #[test]
    fn proxy_network_patch_failure_applies_no_prefix() {
        let config = TomlConfig::default();

        let error = patch_proxy_networks(
            &config,
            vec![
                proxy_add("10.90.0.0/24", None),
                proxy_add("10.91.0.0/24", Some("10.92.0.0/16")),
            ],
        )
        .unwrap_err();

        assert!(error.to_string().contains("Mapped CIDR"));
        assert!(
            config.get_proxy_cidrs().is_empty(),
            "a failing list patch must not leave a partially applied prefix"
        );
    }

    fn portal_config() -> TomlConfig {
        let config = TomlConfig::default();
        config.set_vpn_portal_config(VpnPortalConfig {
            wireguard_listen: "0.0.0.0:51820".parse().unwrap(),
            wireguard_private_key: None,
            clients: vec![VpnPortalClientConfig {
                name: "alice".to_owned(),
                virtual_ip: "10.0.0.2/24".parse().unwrap(),
                groups: Vec::new(),
            }],
        });
        config
    }

    fn configured_names(config: &TomlConfig) -> Vec<String> {
        config
            .get_vpn_portal_config()
            .unwrap()
            .clients
            .into_iter()
            .map(|client| client.name)
            .collect()
    }

    fn add(name: &str, ip: &str) -> VpnPortalClientPatch {
        VpnPortalClientPatch {
            action: ConfigPatchAction::Add as i32,
            client: Some(ClientPb {
                name: name.to_owned(),
                virtual_ip: ip.to_owned(),
                groups: Vec::new(),
            }),
        }
    }

    fn remove(name: &str) -> VpnPortalClientPatch {
        VpnPortalClientPatch {
            action: ConfigPatchAction::Remove as i32,
            client: Some(ClientPb {
                name: name.to_owned(),
                virtual_ip: String::new(),
                groups: Vec::new(),
            }),
        }
    }

    #[test]
    fn vpn_portal_client_patches_add_remove_and_clear() {
        let config = portal_config();

        apply_vpn_portal_client_patches(&config, vec![add("bob", "10.0.0.3/24")]).unwrap();
        assert_eq!(configured_names(&config), ["alice", "bob"]);

        apply_vpn_portal_client_patches(&config, vec![remove("alice")]).unwrap();
        assert_eq!(configured_names(&config), ["bob"]);

        apply_vpn_portal_client_patches(
            &config,
            vec![VpnPortalClientPatch {
                action: ConfigPatchAction::Clear as i32,
                client: None,
            }],
        )
        .unwrap();
        assert!(configured_names(&config).is_empty());
    }

    #[test]
    fn vpn_portal_client_patches_reject_missing_prerequisites() {
        let bare = TomlConfig::default();
        let error =
            apply_vpn_portal_client_patches(&bare, vec![add("alice", "10.0.0.2")]).unwrap_err();
        assert!(error.to_string().contains("not configured"));

        let config = portal_config();
        let error = apply_vpn_portal_client_patches(&config, vec![remove("ghost")]).unwrap_err();
        assert!(error.to_string().contains("not found"));

        let error =
            apply_vpn_portal_client_patches(&config, vec![add("bob", "not-an-ip")]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid VPN portal client virtual CIDR")
        );
    }
}
