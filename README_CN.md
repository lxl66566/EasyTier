# EasyTier

[![Github release](https://img.shields.io/github/v/tag/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/releases)
[![GitHub](https://img.shields.io/github/license/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/issues)
[![GitHub Core Actions](https://github.com/EasyTier/EasyTier/actions/workflows/core.yml/badge.svg)](https://github.com/EasyTier/EasyTier/actions/workflows/core.yml)
[![GitHub GUI Actions](https://github.com/EasyTier/EasyTier/actions/workflows/gui.yml/badge.svg)](https://github.com/EasyTier/EasyTier/actions/workflows/gui.yml)
[![GitHub Test Actions](https://github.com/EasyTier/EasyTier/actions/workflows/test.yml/badge.svg)](https://github.com/EasyTier/EasyTier/actions/workflows/test.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/EasyTier/EasyTier)

[简体中文](/README_CN.md) | [English](/README.md)

> ✨ 一个由 Rust 和 Tokio 驱动的简单、安全、去中心化的异地组网方案

<p align="center">
<img src="assets/config-page.png" width="300" alt="配置页面">
<img src="assets/running-page.png" width="300" alt="运行页面">
</p>

📚 **[完整文档](https://easytier.cn)** | 🖥️ **[Web 控制台](https://easytier.cn/web)** | 📝 **[下载发布版本](https://github.com/EasyTier/EasyTier/releases)** | 🧩 **[第三方工具](https://easytier.cn/guide/installation_gui.html#%E7%AC%AC%E4%B8%89%E6%96%B9%E5%9B%BE%E5%BD%A2%E7%95%8C%E9%9D%A2)** | ❤️ **[赞助](#赞助)**

## 特性

### 核心特性

- 🔒 **去中心化**：节点平等且独立，无需中心化服务
- 🚀 **易于使用**：支持通过网页、客户端和命令行多种操作方式
- 🌍 **跨平台**：支持 Win/MacOS/Linux/FreeBSD/Android 和 X86/ARM/MIPS 架构
- 🔐 **安全**：AES-GCM 或 WireGuard 加密，防止中间人攻击

### 高级功能

- 🔌 **高效 NAT 穿透**：支持 UDP 和 IPv6 穿透，可在 NAT4-NAT4 网络中工作
- 🌐 **子网代理**：节点可以共享子网供其他节点访问
- 🔄 **智能路由**：延迟优先和自动路由选择，提供最佳网络体验
- ⚡ **高性能**：整个链路零拷贝，支持 TCP/UDP/WSS/WG 协议

### 网络优化

- 📊 **UDP 丢包抗性**：KCP/QUIC 代理在高丢包环境下优化延迟和带宽
- 🔧 **Web 管理**：通过 Web 界面轻松配置和监控
- 🛠️ **零配置**：静态链接的可执行文件，简单部署

## 快速开始

### 📥 安装

选择最适合您需求的安装方式：

Linux（推荐）：
```bash
curl -fsSL "https://github.com/EasyTier/EasyTier/blob/main/script/install.sh?raw=true" | sudo bash -s install
```

Homebrew（MacOS/Linux）：
```bash
brew tap brewforge/chinese
brew install --cask easytier-gui
```

Windows（推荐，请以管理员权限运行）：
```powershell
irm "https://github.com/EasyTier/EasyTier/blob/main/script/install.ps1?raw=true" | iex
```

通过 cargo 安装（最新开发版本）：
```bash
cargo install --git https://github.com/EasyTier/EasyTier.git easytier
```

[下载预编译文件](https://github.com/EasyTier/EasyTier/releases)（推荐，支持所有平台）

[通过 Docker 安装](https://easytier.cn/guide/installation.html#%E5%AE%89%E8%A3%85%E6%96%B9%E5%BC%8F)

[安装 OpenWrt ipk 软件包](https://github.com/EasyTier/luci-app-easytier)

附加步骤：

[一键注册系统服务](https://easytier.cn/guide/network/oneclick-install-as-service.html)（系统启动时自动后台运行）

### 🚀 基本用法

#### 使用共享节点快速组网

EasyTier 支持使用共享节点快速组网。当您没有公网 IP 时，可以使用公共共享节点。节点会自动尝试 NAT 穿透并建立 P2P 连接。当 P2P 失败时，数据将通过共享节点中继。

使用共享节点时，每个进入网络的节点需要提供相同的 `--network-name` 和 `--network-secret` 参数作为网络的唯一标识符。

以两个节点为例（请使用更复杂的网络名称以避免冲突）：

1. 在节点 A 上运行：

```bash
# 以管理员权限运行
sudo easytier-core -d --network-name abc --network-secret abc -p tcp://<共享节点IP>:11010
```

2. 在节点 B 上运行：

```bash
# 以管理员权限运行
sudo easytier-core -d --network-name abc --network-secret abc -p tcp://<共享节点IP>:11010
```

执行成功后，可以使用 `easytier-cli` 检查网络状态：

```text
| ipv4         | hostname       | cost  | lat_ms | loss_rate | rx_bytes | tx_bytes | tunnel_proto | nat_type | id         | version         |
| ------------ | -------------- | ----- | ------ | --------- | -------- | -------- | ------------ | -------- | ---------- | --------------- |
| 10.126.126.1 | abc-1          | Local | *      | *         | *        | *        | udp          | FullCone | 439804259  | 2.6.2-70e69a38~ |
| 10.126.126.2 | abc-2          | p2p   | 3.452  | 0         | 17.33 kB | 20.42 kB | udp          | FullCone | 390879727  | 2.6.2-70e69a38~ |
|              | PublicServer_a | p2p   | 27.796 | 0.000     | 50.01 kB | 67.46 kB | tcp          | Unknown  | 3771642457 | 2.6.2-70e69a38~ |
```

您可以测试节点之间的连通性：

```bash
# 测试连通性
ping 10.126.126.1
ping 10.126.126.2
```

注意：如果无法 ping 通，可能是防火墙阻止了入站流量。请关闭防火墙或添加允许规则。

为了提高可用性，您可以同时连接多个共享节点：

```bash
# 连接多个共享节点
sudo easytier-core -d --network-name abc --network-secret abc -p tcp://<公共节点IP>:11010 -p udp://<公共节点IP>:11010
```

#### 去中心化组网

EasyTier 本质上是去中心化的，没有服务器和客户端的区分。只要一个设备能与虚拟网络中的任何节点通信，它就可以加入虚拟网络。以下是如何设置去中心化网络：

1. 启动第一个节点（节点 A）：

```bash
# 启动第一个节点
sudo easytier-core -i 10.144.144.1
```

启动后，该节点将默认监听以下端口：
- TCP：11010
- UDP：11010
- WebSocket：11011
- WebSocket SSL：11012
- WireGuard：11013

2. 连接第二个节点（节点 B）：

```bash
# 使用第一个节点的公网 IP 连接
sudo easytier-core -i 10.144.144.2 -p udp://第一个节点的公网IP:11010
```

3. 验证连接：

```bash
# 测试连通性
ping 10.144.144.2

# 查看已连接的对等节点
easytier-cli peer

# 查看路由信息
easytier-cli route

# 查看本地节点信息
easytier-cli node
```

更多节点要加入网络，可以使用 `-p` 参数连接到网络中的任何现有节点：

```bash
# 使用任何现有节点的公网 IP 连接
sudo easytier-core -i 10.144.144.3 -p udp://任何现有节点的公网IP:11010
```

### 🔍 高级功能

#### 子网代理

假设网络拓扑如下，节点 B 想要与其他节点共享其可访问的子网 10.1.1.0/24：

```mermaid
flowchart LR

subgraph 节点 A 公网 IP 22.1.1.1
nodea[EasyTier<br/>10.144.144.1]
end

subgraph 节点 B
nodeb[EasyTier<br/>10.144.144.2]
end

id1[[10.1.1.0/24]]

nodea <--> nodeb <-.-> id1
```

要共享子网，在启动 EasyTier 时添加 `-n` 参数：

```bash
# 与其他节点共享子网 10.1.1.0/24
sudo easytier-core -i 10.144.144.2 -n 10.1.1.0/24
```

子网代理信息将自动同步到虚拟网络中的每个节点，每个节点将自动配置相应的路由。您可以验证子网代理设置：

1. 检查路由信息是否已同步（proxy_cidrs 列显示代理的子网）：

```bash
# 查看路由信息
easytier-cli route
```

![路由信息](/assets/image-3.png)

2. 测试是否可以访问代理子网中的节点：

```bash
# 测试到代理子网的连通性
ping 10.1.1.2
```

#### WireGuard 集成

EasyTier 可以作为 WireGuard 服务器，允许任何安装了 WireGuard 客户端的设备（包括 iOS 和 Android）访问 EasyTier 网络。以下是设置示例：

```mermaid
flowchart LR

ios[[iPhone<br/>已安装 WireGuard]]

subgraph 节点 A 公网 IP 22.1.1.1
nodea[EasyTier<br/>10.144.144.1]
end

subgraph 节点 B
nodeb[EasyTier<br/>10.144.144.2]
end

id1[[10.1.1.0/24]]

ios <-.-> nodea <--> nodeb <-.-> id1
```

1. 启动启用 WireGuard 门户的 EasyTier：

```bash
# 将一个 WireGuard 客户端注册为虚拟 peer 10.144.144.3
sudo easytier-core -i 10.144.144.1 \
  --network-secret portal-secret \
  --vpn-portal wg://0.0.0.0:11013 \
  --vpn-portal-private-key "$(wg genkey)" \
  --vpn-portal-client phone=10.144.144.3
```

2. 获取 WireGuard 客户端配置：

```bash
# 获取 WireGuard 客户端配置
easytier-cli vpn-portal
```

3. 如果输出配置中的 `Peer.Endpoint` 是通配地址，将其替换为 EasyTier
   节点的公网 IP/域名后即可导入。`Interface.Address` 只是客户端本地地址，
   可以改为任意 IPv4 地址；EasyTier 会把它转换成已注册的虚拟 peer 地址。

#### 自建公共共享节点

您可以运行自己的公共共享节点来帮助其他节点相互发现。公共共享节点只是一个普通的 EasyTier 网络（具有相同的网络名称和密钥），其他网络可以连接到它。

要运行公共共享节点：

```bash
# 公共共享节点无需指定 IPv4 地址
sudo easytier-core --network-name mysharednode --network-secret mysharednode
```

网络设置成功后，您可以轻松配置它以在系统启动时自动启动。请参阅 [一键注册服务指南](https://easytier.cn/en/guide/network/oneclick-install-as-service.html) 了解如何将 EasyTier 注册为系统服务。

#### 传输层安全

`quic://` 隧道运行真正的 TLS 1.3 握手（quinn/rustls，ring provider），QUIC 传输层自身即具备加密与完整性保护。服务器使用自签证书，其私钥持久化在用户的 EasyTier 状态目录中（如 Linux 的 `~/.local/share/easytier/quic-server-key.pem`、Windows 的 `%LOCALAPPDATA%\easytier\`），因此证书指纹跨重启保持稳定。默认情况下客户端不校验证书身份，主动中间人仍可冒充服务器。可在节点 URL 的 fragment 中固定服务器证书指纹来防范：

```bash
sudo easytier-core -p 'quic://server.example.com:11010#fingerprint=sha256:<64位十六进制>'
```

节点 `quic://` 监听器启动时会在日志中打印其证书指纹。固定了指纹的连接一旦不匹配即被拒绝（fail-closed）。

对于尚未升级到 TLS 传输的对端，旧的仅校验和（明文）会话保留为显式开关：在节点 URL 后附加 `#plain=1` 以明文拨号，或在监听 URL 后附加（`-l 'quic://0.0.0.0:11010#plain=1'`）以接收明文客户端。`#plain=1` 监听器只接收旧版客户端——TLS 与明文无法共用同一端口——且任何 TLS 到明文的回退都不会自动发生。明文模式不提供加密与认证，并会打印警告；此类链路请保持 `enable_encryption`（默认）或 secure mode 开启。

内部 `wg://` 隧道的 WireGuard 静态密钥改用 argon2id（内存困难型，19 MiB / 2 轮）从网络名称与网络密钥派生，捕获一次握手不再能对弱网络密钥做高速离线爆破；并且连接两端派生不同密钥（dialer 半与 listener 半），节点间不再共享同一把静态密钥。这是一个破坏性变更：仍使用旧快速哈希派生的节点无法连接，接受侧会检测到不匹配并打印日志。请将两端都升级，或对单条链路显式选用旧密钥 `#legacy-keys=1`：

```bash
# 拨号一个尚未升级的对端
sudo easytier-core -p 'wg://old-node.example.com:11013#legacy-keys=1'
# 或用专用监听器接收旧版节点
sudo easytier-core -l 'wg://0.0.0.0:11013#legacy-keys=1'
```

`#legacy-keys=1` 监听器只接收旧版节点，旧派生属于安全性降级并会打印警告，且任何自动回退都不会发生。

`wss://` 隧道虽然使用 TLS，但默认情况下客户端接受任意服务器证书，主动中间人仍可冒充服务器。可在节点 URL 的 fragment 中固定服务器证书指纹来防范：

```bash
sudo easytier-core -p 'wss://server.example.com:11010#fingerprint=sha256:<64位十六进制>'
```

节点 `wss://` 监听器启动时会在日志中打印其证书指纹。固定了指纹的连接一旦不匹配即被拒绝。注意：当前证书在每次进程重启时会重新生成，指纹随之变化，已固定的对端会拒绝连接（fail-closed），需要重新固定。

关于数据面加密算法选项 `encryption_algorithm`：`aes-gcm`（默认）、`aes-256-gcm`、`chacha20` 均为带认证的加密；而 `xor` 仅为混淆手段——没有完整性与防重放保护，报文可被被动篡改而不被发现。该选项仅为兼容旧版本节点而保留，选中时会打印警告，除非确有旧对端需要，否则应避免使用。

连接中央配置服务器（`easytier-web`）的节点也有类似问题：Web 管理隧道虽经 Noise 加密，但若不认证服务器身份，主动中间人可以中继会话并截获提交的管理凭证。较新的服务端因此改用带服务端静态密钥的 Noise_XX 认证握手。在配置服务器 URL 的 fragment 中固定其密钥指纹即可启用 fail-closed 校验：

```bash
sudo easytier-core --config-server 'udp://config-server.example.com:22020/mytoken#fingerprint=sha256:<64位十六进制>'
```

`easytier-web` 启动时会在日志中打印该指纹（密钥持久化在数据库旁的 `<db>.noise-static-key` 文件中，重启后保持不变）。配置了 pin 的客户端在服务端不支持认证握手或指纹不匹配时会拒绝连接（fail-closed）；未配置 pin 的客户端会在服务端支持时自动升级，对旧服务端回退到旧的未认证握手并打印警告。

## 相关项目

- [ZeroTier](https://www.zerotier.com/)：用于连接设备的全球虚拟网络。
- [TailScale](https://tailscale.com/)：旨在简化网络配置的 VPN 解决方案。

### 联系我们

- 💬 **[Telegram 群组](https://t.me/easytier)**
- 👥 **QQ 群**
  - 一群 [949700262](https://qm.qq.com/q/wFoTUChqZW)
  - 二群 [837676408](https://qm.qq.com/q/4V33DrfgHe)
  - 三群 [957189589](https://qm.qq.com/q/YNyTQjwlai)

## 许可证

EasyTier 在 [LGPL-3.0](https://github.com/EasyTier/EasyTier/blob/main/LICENSE) 许可下发布。

## 使用规范

请仅将 EasyTier 用于合法用途，并遵守适用的法律法规。使用者有责任确保其已获授权连接和管理相关网络与设备。

## 赞助

本项目的 CDN 加速和安全防护由腾讯云 EdgeOne 赞助。

<p align="center">
<a href="https://edgeone.ai/?from=github" target="_blank">
<img src="assets/edgeone.png" width="200">
</a>
</p>

特别感谢 [浪浪云](https://langlangy.cn/?i26c5a5) 和 [雨云](https://www.rainyun.com/NjM0NzQ1_) 赞助我们的公共服务器。

<p align="center">
<a href="https://langlangy.cn/?i26c5a5" target="_blank">
<img src="assets/langlang.png" width="200">
</a>
<a href="https://langlangy.cn/?i26c5a5" target="_blank">
<img src="assets/raincloud.png" width="200">
</a>
</p>

如果您觉得 EasyTier 有帮助，请考虑赞助我们。软件开发和维护需要大量的时间和精力，您的赞助将帮助我们更好地维护和改进 EasyTier。

<p align="center">
<img src="assets/wechat.png" width="200">
<img src="assets/alipay.png" width="200">
</p>
