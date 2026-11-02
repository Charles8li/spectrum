# Spectrum

Spectrum is an experimental Rust project for remote application access over a
local network. It uses a client-and-agent design to exchange application visuals
and control messages between devices.

## Status

The Windows window-viewing preview provides a separate, read-only application
window path:

- Select one local application window before sharing starts.
- View its updates in a native client window over a mutually authenticated,
  hybrid-only TLS 1.3 QUIC connection.
- Discover a device on the local network and pair with a one-time code.
- Protect local identity keys with the current Windows account's
  data-protection API.
- Stop when the selected window closes, changes size, becomes unavailable, or
  its pairing or authorization ends.

This is an early preview for controlled environments, not a production release.
Start with the [Windows window-viewing guide](docs/WINDOW-VIEWING.md).

## Project scope

Spectrum focuses on interactive and programmatic access to applications on
explicitly authorized devices. Authentication, application permissions, and the
handling of transmitted content are central to making that access usable.

Application windows and structured commands are the main direction. Full-desktop
remote access remains a conventional capability in the project. Its earlier
display-capture and input implementation is retained in the legacy entry points,
which remain disabled pending integration with the newer permission and storage
paths. A window capture failure never switches to desktop capture.

The project does not claim compatibility with arbitrary applications or automatic
migration of application computation to another device.

## Future vision

Planned capabilities:

- Control supported applications through typed, structured commands.
- View and control one application window you authorize.
- Request screenshots and opt-in recordings of that authorized window.
- Give programs and AI agents structured information about supported controls.
- Launch registered applications and revoke access when needed.
- Pair trusted devices on your LAN and establish encrypted sessions with hybrid
  post-quantum key exchange.
- Exchange session content directly between paired devices, without developer-side
  collection.

## Repository layout

- `crates/agent`: the window-sharing entry point and retained desktop prototype.
- `crates/client`: the window viewer, diagnostics, and retained desktop client.
- `crates/common`: typed commands, authorization, transport, and frame limits.
- `crates/window`: Windows window selection, capture, rendering, and identity
  storage.
- `proto/lanrdp.proto`: the retained legacy protocol schema.

## Current limitations

- The window preview is Windows-only and read-only. Input, application launch,
  recording, and control metadata are not exposed by its commands yet.
- Frames are raw BGRA, limited to 1920 by 1080 pixels, with at most two frame
  requests per second. This is a request limit, not a performance guarantee.
- Resizing, minimizing, or closing the selected window stops sharing. Select
  the window again to start another session.
- One share command serves one session for a bounded time. Reconnection and
  unattended access are not enabled.
- Automatic discovery currently uses IPv4 on the same local subnet. Network
  isolation or firewall settings may prevent devices from finding each other.
- Pairing codes expire and allow one connection attempt. Certificate
  authentication uses conventional signatures; hybrid key exchange alone does
  not make the whole product post-quantum secure.
- Legacy PIN/session files, shell, file-transfer, and input handlers are retained
  in the disabled prototype, outside the window-viewing commands.
- Capture support depends on Windows, its graphics driver, and the application.
  There is no verified compatibility matrix or production security assurance.

The prototype is unsuitable for real credentials, sensitive content, or
unattended remote access. Transport encryption alone does not establish a trusted
peer or authorize application control.

## License

Spectrum is licensed under the [MIT License](LICENSE). Dependencies retain their
respective licenses and notices.
