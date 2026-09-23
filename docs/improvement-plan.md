# EasyTier fork 改进工作队列

本文件是 fork 维护用的改进工作队列，基于 2026-09-24 对 ext 分支（基线 286e0f4a，69 个提交）之后代码的全面 review 整理而成，条目按收益从高到低排序。每项完成后由管理者在"状态"栏标记完成状态（未开始 / 进行中 / 已完成）并填写落地提交哈希；废弃的条目标记"已放弃"并注明原因。所有条目均已对照 ext 分支已完成的 69 个提交去重，不会与已合入的工作重复。

### IMP-01 修复 Throughput 统计的非原子读写（数据竞争，UB）

- 收益：`Throughput` 用 `UnsafeCell<u64>` 做非原子 `+=`，与已修复的 `UnsafeCounter`（提交 1ffe464b）是同一类正式数据竞争。隧道收发任务写、ping 任务读同一 `Arc<Throughput>`（`StatsRecorderTunnelFilter` 写，`PingIntervalController` 读），release 构建为 panic=abort，属于必须消除的 UB。
- 工作量：S
- 涉及范围：
  - easytier-core/src/tunnel/stats.rs
- 具体改动：把 `Throughput` 的四个 `UnsafeCell<u64>` 字段换成 `AtomicU64`，`record_tx_bytes`/`record_rx_bytes` 用 `fetch_add`（Relaxed），读取用 `load`（Relaxed），`Clone` 实现按当前值构造。公开 API 签名不变，调用方（peer_conn_ping.rs、filter.rs、peer_conn.rs）无需改动。可参照 foundation/stats.rs 中 `UnsafeCounter` 的既有改法。
- 验证方式：`cargo test -p easytier-core --lib`；在 stats.rs 内新增并发冒烟测试（多线程同时 record 与读取，断言计数单调不减）。
- 状态：已完成（提交：45b66855）

### IMP-02 消除 ACL 规则统计的裸指针改写（数据竞争，UB）

- 收益：`inc_cache_entry_stats` 通过 `rule_stats.stat.as_ref().unwrap() as *const StatItem as *mut StatItem` 改写 `Arc<RuleStats>` 内部的计数，绕过借用检查且无同步。`process_packet` 同时被接收路径（PeerPacketRouter 任务）和 NIC 出站路径（`run_nic_packet_process_pipeline`）调用，两个任务并发命中同一规则统计即数据竞争；ACL 热路径上的 UB，与 IMP-01 同级。
- 工作量：M
- 涉及范围：
  - easytier-core/src/peers/acl/processor.rs
- 具体改动：在 processor.rs 内新增内部类型 `AclRuleStat { packet_count: AtomicU64, byte_count: AtomicU64 }`，`FastLookupRule.rule_stats` 与 `AclCacheEntry.rule_stats_vec` 改存 `Arc<AclRuleStat>`；`inc_cache_entry_stats` 改为 `fetch_add` 并删除裸指针代码；`get_rules_stats` 在导出时把原子值装配成 proto 的 `StatItem`。构造点在 processor.rs 第 254、851 行附近。
- 验证方式：`cargo test -p easytier-core --lib`（acl 模块已有大量测试覆盖统计导出）；新增双线程并发 `process_packet` 断言计数和等于发包数的测试。
- 状态：已完成（提交：47d597b4）

### IMP-03 让 strict_crypto 可以经管理面（web/RPC）下发

- 收益：`strict_crypto`（提交 16db8fd1）只能通过 toml/CLI 配置；`NetworkConfig` proto（easytier-proto/proto/api_manage.proto）没有对应字段，`gen_config`（config/api_input.rs）也不会设置它，所以由 web 控制器或 RPC 启动的实例永远以 strict_crypto=false 运行，运营者的强制严格加密策略在托管设备上静默失效。这是 fork 自身安全特性的覆盖缺口。
- 工作量：M
- 涉及范围：
  - easytier-proto/proto/api_manage.proto
  - easytier-core/src/config/api_input.rs
  - easytier-core/src/config/toml.rs
  - easytier-core/src/management/full/config_patch.rs
- 具体改动：在 `NetworkConfig` 的 flags/设置中加 `strict_crypto` 布尔字段；`gen_config` 调用 `cfg.set_strict_crypto`，`new_from_config` 回读；config_patch.rs 若维护网络级开关区段则同步纳入。保持默认 false 不变，避免改变现有托管实例行为。
- 验证方式：重新生成 proto 后 `cargo test -p easytier-core --lib`（新增 NetworkConfig 与 toml 的往返测试：设置 true 经 gen_config/new_from_config 不丢失）；`cargo check -p easytier-web`。
- 状态：已完成（提交：2636db4f）

### IMP-04 数据面逐包日志限频，防远程日志洪水

- 收益：三个逐包日志可被对端或本机路由状态触发且无限频：`handle_packet` 解密失败逐包 `error!`（peer_manager.rs 约 3337 行，伪造加密包头即可打满日志 IO）、`send_msg_by_ip` 无路由时逐包 `info!("no peer id for ip")`（约 2943 行，缺路由的子网每包一条）、转发失败 `error!`（约 3326 行）。fork 已为明文丢弃（PLAINTEXT_DROP_LOG_INTERVAL）和 portal 源不匹配告警做了限频，这里是同方向遗漏的点。
- 工作量：S
- 涉及范围：
  - easytier-core/src/peers/peer_manager.rs
- 具体改动：复用 `reject_plaintext_packet` 的"计数器 + 第 1 次及每 N 次打印"模式：解密失败与无路由两处各加一个 AtomicU64 计数，首次 warn、之后每 64 次一条，并保留计数指标便于排查；"no peer id for ip" 同时把级别降到 warn/debug。
- 验证方式：`cargo test -p easytier-core --lib`；新增单元测试断言 N 次触发只产生 1 条日志（用 tracing mock subscriber 计数）。
- 状态：未开始（提交：）

### IMP-05 argon2id 派生移出全局缓存锁

- 收益：`derive_domain_key_argon2id`（kdf.rs 101-115 行）在持有进程级 `DOMAIN_KEY_CACHE` 互斥锁的状态下执行 argon2id（约 19 MiB 内存、毫秒到几十毫秒级）。一次冷派生会阻塞所有域的所有缓存命中：握手证明（secret-challenge-v2）、wg:// 隧道密钥、PeerManager 重建共用这把锁，公共服务器上多网络并发建连时造成可观的建连延迟毛刺。
- 工作量：S
- 涉及范围：
  - easytier-core/src/tunnel/encrypt/kdf.rs
- 具体改动：先查缓存命中则直接返回；未命中时释放锁计算 argon2id，再重新加锁做 double-check 插入（并发同 secret 派生两次无害，结果确定）。KEY_CACHE_CAP 淘汰逻辑保持在第二次加锁内。
- 验证方式：`cargo test -p easytier-core --lib`（已有 `domain_key_cache_hit_skips_argon2` 等测试继续通过）；新增测试断言两个线程对不同 secret 冷派生期间第三个线程的缓存命中不被阻塞（用短超时断言）。
- 状态：已完成（提交：a9dd443a）

### IMP-06 IPv4 广播/组播 fanout 并发发送

- 收益：`send_msg_by_ip`（peer_manager.rs 2970-3029 行）对 `dst_peers` 逐个 `send_msg_internal(...).await`，串行等待。广播地址（`is_all_peers_broadcast_ipv4`，如 mDNS/255.255.255.255）在 n 节点 mesh 中每包 n 次串行 await；其中一个目的地走中继握手或通道背压时整批停顿，广播流量大时显著拖慢数据面。
- 工作量：M
- 涉及范围：
  - easytier-core/src/peers/peer_manager.rs
- 具体改动：fanout 循环内每个目的地克隆消息、设置 per-destination 头并加密后，把 `send_msg_internal` 的 future 收集进 `futures::future::join_all`（或 JoinSet）并发执行，最后聚合 errs 返回。保持最后一份数据取 `msg.take()` 的零拷贝惯例、`mark_recent_traffic` 与错误聚合语义不变。
- 验证方式：`cargo test -p easytier-core --lib`（peers/tests.rs 的多播相关用例）；手工在三节点环境发广播流量确认各端均收到且无乱序导致的解密失败日志。
- 状态：未开始（提交：）

### IMP-07 压缩路径消除双重分配并按已知长度解压

- 收益：zstd 开启时每包两次浪费：`compress` 先压到独立 `Vec` 再 `truncate + extend_from_slice` 拷回包内（compressor.rs 71-91 行）；`decompress` 用 `data.len() * 2^i` 逐级猜输出长度重试（zstd.rs 46-66 行），而解压后的精确长度 `pm_header.len` 在解压前就已知（compressor.rs 119 行已用它做事后校验）。高压缩比流量最多白试 4 次并多次分配。
- 工作量：M
- 涉及范围：
  - easytier-core/src/packet/compressor.rs
  - easytier-core/src/packet/compressor/zstd.rs
- 具体改动：`decompress_raw` 增加期望输出长度参数，首参即用 `pm_header.len`，猜长度循环仅作为长度字段被伪造时的兜底；`compress` 改为在包缓冲尾部预留空间直接写入（zstd bulk 支持输出到调用方切片），去掉中间 Vec 与一次拷贝；长度不匹配仍按现有逻辑报错。
- 验证方式：`cargo test -p easytier-core --lib`（compressor 现有往返测试）；新增高压缩比用例（重复字节填充）断言一次解压成功且结果与原始一致。
- 状态：未开始（提交：）

### IMP-08 quic_proxy 消除生产路径 unwrap/expect 与循环语义错误

- 收益：`QuicProxy::prepare` 中 `Endpoint::new_with_abstract_socket(...).unwrap()` 与 `default_runtime().unwrap()`（quic_proxy.rs 681-688 行）在端点构造失败时直接 panic（release panic=abort 整进程退出），而该函数本就返回 `anyhow::Result`；`QuicPacketSender::run` 对 `packet.segment` 的 `expect`（434 行）同样属生产 panic 点。另外 444-447 行非法 packet_type 时 `continue` 落在内层分段循环里，同一坏包每个分段各打一条 error，属日志放大。
- 工作量：S
- 涉及范围：
  - easytier/src/gateway/quic_proxy.rs
- 具体改动：`prepare` 中两处 unwrap 改为 `?` 传播并带 context；`segment` 的 `expect` 改为 `error! + continue`（外层 packet 循环）；分段循环加标签，非法 packet_type 用 `continue 'packet` 跳过整个包。
- 验证方式：`cargo check -p easytier`；`cargo test -p easytier --lib`（quic_proxy 测试模块已覆盖 sender/receiver 主体路径）。
- 状态：未开始（提交：）

### IMP-09 collect_network_infos 单实例失败不拖垮整体列表

- 收益：web 面板每次拉取网络列表时，`collect_network_infos`（instance/manager.rs 522-533 行）对任一实例的 `network_instance_running_info` 出错就用 `?` 中止整个 BTreeMap，process_rpc.rs 的 `collect_network_info`（638-658 行）同样。一个异常实例（恰在启动/崩溃边缘）让面板完全无法展示任何网络，属管理面可用性问题。
- 工作量：S
- 涉及范围：
  - easytier-core/src/instance/manager.rs
  - easytier-core/src/management/full/process_rpc.rs
- 具体改动：两处循环把 `?` 改为 match：失败时 `tracing::warn!` 记录实例 id 与错误并跳过（或插入带 error_msg 的降级条目），成功条目照常返回。函数签名不变。
- 验证方式：`cargo test -p easytier-core --lib`；新增测试构造一个 is_ready 但内部报错的实例场景（或直接单测 process_rpc 分支），断言其余实例信息仍返回。
- 状态：未开始（提交：）

### IMP-10 UDP 会话包构建去掉 payload 区域零填充

- 收益：`zcpacket_from_udp_session_payload`（tunnel/udp.rs 24-36 行）对每个收到的不带 EasyTier 头的 UDP 数据报执行 `BytesMut::new() + resize(header+payload, 0) + copy_from_slice`：先 memset 整个 payload 区域（最大 64 KiB）再整体拷贝一次，接收热路径上每包多一次全量写。WireGuard/QUIC 代理等 `Bytes` 型会话数据都走这条路径。
- 工作量：S
- 涉及范围：
  - easytier-core/src/tunnel/udp.rs
- 具体改动：改为 `BytesMut::with_capacity(UDP_TUNNEL_HEADER_SIZE + payload.len())`，先 `extend_from_slice(&[0u8; UDP_TUNNEL_HEADER_SIZE])`（或常量零头数组）再 `extend_from_slice(payload)`，随后照旧填 UDPTunnelHeader。容量精确、payload 区只写一次。
- 验证方式：`cargo test -p easytier-core --lib`；`cargo test -p easytier --lib`（udp 隧道与 wg 引擎回环测试覆盖该路径）。
- 状态：未开始（提交：）

### IMP-11 关停窗口的 unwrap 加固（panic=abort 下的防御）

- 收益：`PeerRpcPacketProcessor::try_process_packet_from_peer` 的 `peer_rpc_tspt_sender.send(packet).unwrap()`（peer_manager.rs 546 行）在 RPC 接收任务已退出而包处理管线仍在转发 TaRpc/RpcReq/RpcResp 包的关停窗口内会 panic 整进程；`start_peer_recv` 的 `take().unwrap()`（1917 行）与 foreign_network/mod.rs 548-549 行同型，run 被二次调用即 abort。这些是"当前不可达但一处改动就变成 abort"的地雷，与已修复的 P3-17 同类。
- 工作量：S
- 涉及范围：
  - easytier-core/src/peers/peer_manager.rs
  - easytier-core/src/peers/foreign_network/mod.rs
- 具体改动：546 行的 unwrap 改为 `warn! + return None`（丢包优于 abort）；两处 `take().unwrap()` 改为 `if let Some(...) else { warn! + return }`。
- 验证方式：`cargo test -p easytier-core --lib`；对 PeerRpcPacketProcessor 补一个"接收端已 drop 时送包不 panic"的单元测试。
- 状态：未开始（提交：）

### IMP-12 ReplayWindow256 补直接单元测试

- 收益：`ReplayWindow256` 在 83de44e1 中被抽成共享模块，是 legacy 数据面防重放的核心原语，但自身没有任何单元测试，行为只被 legacy_aead.rs 的集成路径间接覆盖。窗口滑动、256 边界、`can_accept`/`accept` 一致性等契约一旦被后续改动破坏，只能靠间接用例碰运气发现。
- 工作量：S
- 涉及范围：
  - easytier-core/src/tunnel/encrypt/replay_window.rs
- 具体改动：新增 `mod tests`：顺序接受 0..n 全通过；窗口内乱序接受通过、窗口外旧值拒绝；跨 256 边界滑动后旧 seq 拒绝；对同一 seq，`can_accept` 与 `accept` 返回值一致；`clear` 后状态复位。
- 验证方式：`cargo test -p easytier-core --lib replay_window`。
- 状态：未开始（提交：）

### IMP-13 PeerPacketRouter 单任务密码学卸载评估（先基准，后实施）

- 收益：全节点所有收包（含 AEAD 解密、zstd 解压、ACL）都在 `PeerPacketRouter::run` 单个任务里串行处理（peer_manager.rs 3161-3190 行），中继/公共服务器在多 peer 高吞吐时该任务是单一 CPU 瓶颈。潜在收益是多核扩展，但改动跨模块且涉及每流排序语义，必须先用数据确认瓶颈真实存在。
- 工作量：L
- 涉及范围：
  - easytier-core/src/peers/peer_manager.rs
  - easytier-core/src/foundation/task.rs
- 具体改动：分两步。第一步（无风险）：加一个可开关的每秒包数/处理耗时统计，在真实回放或基准环境确认路由任务 CPU 占比；若占比不高则关闭本项。第二步：Data 包的解密+解压移入有界工作线程池（如 spawn_blocking 池），按 from_peer_id 分组保序（每 peer 序列号 + 有界通道回聚），控制面包与转发路径留在原任务。默认关闭，配置开关灰度。
- 验证方式：第一步用统计输出；第二步 `cargo test -p easytier-core --lib` 全量回归（重点 peers/tests.rs 的乱序与重放用例），并在三节点环境跑吞吐对比。标注：实施前待基准验证。
- 状态：未开始（提交：）

### IMP-14 WgLegacyKeys 探测与派生的小幅收尾

- 收益：`WireGuardAdapter::new`（easytier/src/tunnel/protocol/adapters/wireguard.rs 34-48 行）无条件预派生并常驻 legacy SipHash 密钥对，即使整个部署早已全部升级、永远不会用到 legacy 路径，也保留一份等效弱密钥材料在内存中；且 `new_legacy_from_network_identity` 在构造时即调用 `warn_legacy_keys()`，导致每个节点每次启动都打一次"legacy wg key derivation"降级警告，即使从未出现旧 peer，告警失去信号价值；另外 `WgConfig::new_from_network_identity` 里的 `<[u8; 32]>::try_from(...).unwrap()`（wireguard.rs 163-164 行）是"split_at(32) 之后长度必然 64"的自证 unwrap，属可避免的 panic 面。
- 工作量：S
- 涉及范围：
  - easytier/src/tunnel/protocol/adapters/wireguard.rs
  - easytier/src/tunnel/wireguard.rs
- 具体改动：`legacy_config` 改为 `OnceLock<WgConfig>` 惰性派生，首次 `#legacy-keys=1` 请求或 legacy 握手探测命中时才构造，`warn_legacy_keys()` 一并移到首次实际取用时触发；163-164 行 unwrap 改为显式 `try_into().map_err(...)?` 或 debug_assert + expect 带说明。
- 验证方式：`cargo test -p easytier --lib`（wireguard.rs 已有 legacy 互操作与域名分离测试）。
- 状态：未开始（提交：）
