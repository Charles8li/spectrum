# spectrum / LANRDP MVP

This workspace contains a minimal prototype of a LAN remote desktop stack built in Rust. It ships two binaries that exercise the authentication and transport layers end to end:

* `lanrdp-agent` – runs on the controlled device, listens for QUIC/TLS connections, and spawns local shell sessions that stream stdout/stderr back to the caller while consuming stdin over QUIC.
* `lanrdp-client` – negotiates the control channel, persists the shared secret for resumable sessions, and provides both a `connect` sanity check and a fully interactive `shell` command.

## Project layout

* `crates/common` – shared protocol bindings (generated from `proto/lanrdp.proto`), stream framing helpers, HMAC/PSK derivation, and JSON-backed session persistence for both agent and client.
* `crates/agent` – QUIC server that authenticates with either a one-time PIN or a stored PSK, acknowledges session preferences, and hosts one or more PTY-style shell sessions over dedicated QUIC streams.
* `crates/client` – QUIC client with `connect` and `shell` subcommands. It handles pairing/resumption, writes session preferences, opens PTY streams, and forwards stdin/stdout to the remote shell.

## Current capabilities

* Authenticated control channel: PIN-based pairing derives a PSK keyed by the device ID; subsequent connections can resume with the stored PSK and session token without re-entering the PIN.
* Session negotiation: client and agent exchange resolution, frame rate, color, and video codec preferences before opening feature streams.
* Interactive shell: the client requests a shell (`lanrdp client shell ...`), the agent spawns `/bin/sh -i` (or `cmd /K` on Windows), and stdin/stdout/stderr are bridged over a dedicated QUIC stream until the remote process exits.

## Known gaps / next steps

* Shell resize messages are accepted but currently logged without resizing the PTY.

## What was implemented for this iteration?

* End-to-end QUIC/TLS control channel negotiation with PIN-based pairing or PSK resumption, stored in JSON under the user's config directory.
* A PTY-like shell bridge: the agent spawns `/bin/sh -i` (or `cmd /K` on Windows), forwards local stdout/stderr over a dedicated QUIC stream, and writes remote stdin back into the process. This demonstrates the "simultaneously receive and send" requirement in a concrete, measurable way.
* Client-side helpers to request a shell (`lanrdp shell host:port`), stream local keyboard input to the remote shell, print remote output live, and surface the remote exit code once the session ends.
* Shared session configuration parsing so that both `connect` and `shell` support the same `--video/--res/--fps/--color` knobs, plus optional terminal geometry via `--cols/--rows`.
* Runtime handling for video streaming, input injection, and file transfer initiated from the `send` subcommand.

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

> **Note**: Video streaming, input injection and file transfer now have runtime handlers: the agent captures the current screen each frame, injects key and mouse input on receipt, and persists uploaded files to the requested target directory.
