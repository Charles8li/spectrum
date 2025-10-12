# spectrum / LANRDP MVP

This workspace contains a minimal prototype of a LAN remote desktop stack built in Rust. The prototype exposes two binaries that can now drive a complete authenticated control flow and an interactive shell stream:

* `lanrdp-agent` – runs on the controlled device, listens for QUIC/TLS connections, and can spawn local shell sessions that stream stdout/stderr back to the caller while consuming stdin over QUIC.
* `lanrdp-client` – negotiates the control channel, persists the shared secret for resumable sessions, and provides both a `connect` sanity check and a fully interactive `shell` command.

## What was implemented for this iteration?

* End-to-end QUIC/TLS control channel negotiation with PIN-based pairing or PSK resumption, stored in JSON under the user's config directory.
* A PTY-like shell bridge: the agent spawns `/bin/sh -i` (or `cmd /K` on Windows), forwards local stdout/stderr over a dedicated QUIC stream, and writes remote stdin back into the process. This demonstrates the "simultaneously receive and send" requirement in a concrete, measurable way.
* Client-side helpers to request a shell (`lanrdp shell host:port`), stream local keyboard input to the remote shell, print remote output live, and surface the remote exit code once the session ends.
* Shared session configuration parsing so that both `connect` and `shell` support the same `--video/--res/--fps/--color` knobs, plus optional terminal geometry via `--cols/--rows`.

## Building

```
cargo build --workspace
```

## Pairing + interactive shell flow

```
lanrdp-agent --listen 0.0.0.0:8443 --pin 123456
lanrdp-client connect 192.168.1.50:8443 --pin 123456 --video h264 --res 1280x720 --fps 30 --color yuv420
lanrdp-client shell 192.168.1.50:8443 --pin 123456 --cwd /tmp --cols 100 --rows 30
```

The initial connection requires the pairing PIN to derive a pre-shared key (PSK). Session state is persisted for both agent and client so subsequent runs can resume without re-entering the PIN. The `shell` command will honour the stored PSK, so after the first pairing you can omit `--pin` for later runs.

### Shell session anatomy

1. Client issues `ShellOpen` on the control stream describing the desired working directory and terminal size.
2. Agent spawns the local shell process and acknowledges with `ShellOpened{sid}` before accepting a dedicated QUIC bidirectional stream tagged as `STREAM_TYPE_PTY`.
3. Client immediately opens the matching PTY stream and begins pushing stdin chunks while reading stdout/stderr frames in parallel. Both halves use simple length-prefixed frames (`send_bytes`/`recv_bytes`).
4. When the child process terminates, the agent sends `ShellExit{sid, code}` on the control stream; the client surfaces that exit code after draining pending output.

> **Note**: Video streaming, input injection and file transfer remain scaffolded by protobuf definitions and stream headers, but they now sit alongside a functioning bidirectional data path that proves the transport and authentication layers.
