# spectrum / LANRDP MVP

## Overview / 项目概述

This workspace contains a minimal prototype of a LAN remote desktop stack built in Rust. It demonstrates end-to-end authenticated QUIC/TLS sessions, interactive PTY streaming, resumable file transfer, and now a lightweight text user interface that guides operators through the major workflows.

本仓库实现了一个以 Rust 编写的局域网远程桌面原型：通过 QUIC/TLS 进行安全通信，支持交互式终端、支持断点续传的文件传输，并新增了一个简易的文本交互界面，引导用户完成主要操作流程。

## Feature Highlights / 功能亮点

* **Secure pairing / 安全配对** – The client and agent pair with a one-time PIN, derive a pre-shared key, and reuse it for future TLS 1.3 PSK sessions stored under the config directory.
* **Interactive shells / 交互式终端** – The agent spawns a local shell, bridges stdin/stdout over a dedicated QUIC PTY stream, and reports exit codes on the control channel.
* **Resumable uploads / 文件断点续传** – Clients can `send` large files, resume from the last acknowledged offset, and verify SHA-256 digests before completion.
* **Text UI workflow / 文本交互界面** – `lanrdp-client interactive` launches a guided prompt to connect, open shells, or send files without memorising command-line flags.

## Build Prerequisites / 编译依赖

* Rust toolchain (`rustup`, `cargo`, `rustc`) – <https://rustup.rs/>
* A C toolchain for QUIC dependencies if building on Windows/macOS/Linux (e.g. MSVC, Xcode Command Line Tools, or build-essential).

需要先安装 Rust 工具链（`rustup`、`cargo`、`rustc`），以及系统上常见的 C/C++ 编译环境（Windows 上的 MSVC、macOS 的 Xcode Command Line Tools、Linux 的 build-essential 等）。

## Build Instructions / 编译步骤

```bash
cargo build --workspace
```

The `--workspace` flag ensures every crate (agent, client, and shared common crate) is compiled together.

使用 `--workspace` 参数可一次性编译 agent、client 与通用库三部分。

## Running the Components / 运行方式

### 1. Start the agent / 启动被控端

```bash
lanrdp-agent --listen 0.0.0.0:8443 --pin 123456 --mdns off
```

* `--listen` sets the bind address and port.
* `--pin` configures the one-time pairing code.
* `--mdns` can announce the service on the LAN (optional placeholder switch).

`--listen` 指定监听地址与端口，`--pin` 设置初次配对的 PIN 码，`--mdns` 可根据需要开启/关闭局域网广播（目前为占位选项）。

### 2. Pair and test connectivity / 客户端配对并测试连通

```bash
lanrdp-client connect 192.168.1.50:8443 --pin 123456 --video h264 --res 1280x720 --fps 30 --color yuv420
```

This validates QUIC/TLS negotiation, derives and stores the PSK, and applies the requested session preferences.

该命令会完成 QUIC/TLS 握手、根据 PIN 派生并缓存 PSK，同时提交希望的分辨率、帧率和色彩格式。

### 3. Open an interactive shell / 打开交互式终端

```bash
lanrdp-client shell 192.168.1.50:8443 --cwd /tmp --cols 100 --rows 30
```

After the first pairing, the stored PSK allows you to omit `--pin`. Resize events and remote exit codes propagate back to the client.

首次配对后会自动复用 PSK，因此后续可省略 `--pin`。终端大小调整与远程退出码都会返回到客户端。

### 4. Transfer a file / 传输文件

```bash
lanrdp-client send 192.168.1.50:8443 ./big.iso /tmp
```

Large files resume gracefully: the client hashes the source, negotiates the resume offset, streams new chunks, and validates the SHA-256 digest reported by the agent.

大文件传输可断点续传：客户端会计算源文件哈希、协商断点位置、继续发送剩余部分，并根据代理返回的 SHA-256 值进行校验。

### 5. Use the guided text UI / 使用交互式界面

```bash
lanrdp-client interactive
```

Follow the prompts to enter the server address, optional PIN, desired video profile, and choose between the `connect`, `shell`, or `send` workflows. The UI remembers your last inputs during the session for quick iteration.

按照提示输入服务端地址、可选 PIN 码、视频参数等，然后选择“连接测试”、“打开终端”或“文件传输”流程。界面会在当前会话内记住上一次输入，方便多次操作。

## Shell Session Anatomy / Shell 会话流程

1. Client issues `ShellOpen` on the control stream describing the desired working directory and terminal size.
2. Agent spawns the local shell process and acknowledges with `ShellOpened{sid}` before accepting a dedicated QUIC bidirectional stream tagged as `STREAM_TYPE_PTY`.
3. Client immediately opens the matching PTY stream and begins pushing stdin chunks while reading stdout/stderr frames in parallel. Both halves use simple length-prefixed frames (`send_bytes`/`recv_bytes`).
4. When the child process terminates, the agent sends `ShellExit{sid, code}` on the control stream; the client surfaces that exit code after draining pending output.

## Roadmap / 后续计划

* Frame-grab pipelines (DDA / ScreenCaptureKit / PipeWire) feeding H.264 or tile-delta encoders with configurable refresh budgets.
* Mouse/keyboard injection for full desktop control.
* Multi-stream multiplexing for concurrent PTY and file transfers beyond the first session.

接下来的工作包括：完善屏幕捕获与编码链路（支持 H.264 低延迟和瓦片增量模式）、实现完整的鼠标键盘注入、在单条 QUIC 连接中更高效地复用多路流。
