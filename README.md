# ncm-rs

[English](./doc/en/README.md) | 简体中文

[![API Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cloud370/ncm-rs/master/api-status.json)](./API_STATUS.md)
[查看 API 每日可用性报告](./API_STATUS.md)

使用 Rust 编写的高性能、跨平台网易云音乐 API 实现。

它可以作为独立的 HTTP 代理服务器运行，也可以作为 Rust 库集成到项目中。

## 特性

- **高性能**: 轻量且快速，基于 Axum 和 Tokio 构建。
- **全量加密**: 原生实现 `weapi`、`eapi` 和 `linuxapi`。
- **双模式**: 可作为独立 HTTP 代理或 Rust 库使用。
- **智能代理**: 自动加密检测及上游代理支持。

## 作为代理服务器使用

启动服务器以公开通用代理端点。该端点接收请求，在内部处理复杂的加密，并将其转发至网易云服务器。

### 安装与运行

```bash
# 克隆仓库
git clone https://github.com/cloud370/ncm-rs.git
cd ncm-rs

# 运行服务器（默认端口：3331）
cargo run

# 或指定自定义端口
cargo run -- --port 8080

# 或指定全局代理 (HTTP/SOCKS5)
cargo run -- --proxy http://127.0.0.1:7890
```

### 直接 URL 透传 (推荐)

这是使用代理最简单的方法。您可以直接请求任何网易云音乐 API 路径。服务器会根据路径自动检测所需的加密方式。

**示例：**
```bash
# 自动为 /eapi/ 路径使用 EAPI 加密
curl "http://localhost:3331/eapi/cloudsearch/pc?s=Fade&type=1"

# 自动为 /weapi/ 路径使用 WEAPI 加密
curl "http://localhost:3331/weapi/search/get?s=Fade&type=1"
```

您还可以使用 **HTTP 请求头** 或 **查询参数** 配置请求行为：

| 请求头 | 查询参数 | 描述 |
|--------|-------------|-------------|
| `X-NCM-Crypto` | `crypto` | 强制加密类型 (`weapi`, `eapi`, `linuxapi`, `none`) |
| `X-NCM-Network-Proxy` | `proxy` | 使用特定的上游网络代理 (HTTP/SOCKS5) |
| `X-NCM-Retry` | `retry` | 失败时的重试次数 |
| `X-NCM-Timeout` | `timeout` | 请求超时时间（秒） |

### 结构化代理端点

**POST** `http://localhost:3331/proxy`

如果您更喜欢结构化的 JSON 接口：

```bash
curl -X POST http://localhost:3331/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "url": "/weapi/search/get",
    "params": {
        "s": "Fade",
        "type": 1,
        "limit": 3
    }
}'
```

## 作为 Rust 库使用

您可以将 `ncm-rs` 直接集成到您的 Rust 应用程序中。更多高级用法请查看 [examples](./examples) 目录。

### 安装

将此内容添加到您的 `Cargo.toml`：

```toml
[dependencies]
ncm-rs = { git = "https://github.com/cloud370/ncm-rs.git" }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }
```

### 示例

```rust
use ncm_rs::{NcmClient, types::CryptoType};
use reqwest::Method;
use serde_json::json;

#[tokio::main]
async fn main() {
    // 初始化客户端（可选代理，超时时间单位为秒）
    let client = NcmClient::new(None, 30).unwrap();
    
    // 使用 Weapi 发起搜索请求
    let res = client.request(
        Method::POST,
        "/weapi/search/get",
        json!({
            "s": "Se Fue La Luz",
            "type": 1,
            "limit": 5
        }),
        CryptoType::Weapi
    ).await;

    match res {
        Ok(data) => println!("响应内容: {}", data),
        Err(e) => eprintln!("错误: {}", e),
    }
}
```

### 更多示例

详细示例可以在 [examples](./examples) 目录中找到：
- [云端搜索](./examples/cloud_search.rs): 搜索歌曲、艺术家等。
- [歌单详情](./examples/playlist_detail.rs): 获取歌单的完整详情。
- [歌曲 URL](./examples/song_url.rs): 获取歌曲的下载/播放链接。

## 项目结构

- `src/client.rs`: 核心 HTTP 客户端，包含 Cookie 和代理管理。
- `src/server.rs`: 基于 Axum 的 HTTP 服务器实现。
- `src/utils/crypto.rs`: 加密逻辑 (AES, RSA, MD5)。
- `src/lib.rs`: 库入口。
- `src/main.rs`: 命令行界面 (CLI) 入口。

## 许可

本项目采用 [MIT License](./LICENSE) 许可协议。

## 免责声明

本项目仅供 **教育和研究目的** 使用。API 接口和数据归网易云音乐所有。请勿将此项目用于任何非法或商业活动。
