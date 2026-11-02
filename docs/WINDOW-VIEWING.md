# Windows window viewing

The preview shares one explicitly authorized application window. It is read-only:
keyboard and mouse input are not sent to the sharing device.

Use your own devices and non-sensitive content for initial trials. Start with the
built-in test window before selecting another application.

## Requirements

- Windows 10 version 2004 or later, or Windows 11, with an interactive desktop,
  Windows Graphics Capture, and a working Direct3D 11 graphics device.
- Both devices on the same trusted IPv4 subnet. Device discovery uses local
  multicast; isolated wireless clients and some networks may block it.
- A writable private folder on each device. Run without administrator privileges.

The programs do not install services, request elevation, change firewall rules,
record sessions, or enable telemetry. Windows may require private-profile
firewall exceptions for discovery replies and connections. If necessary, limit
exceptions to the relevant executable, authorized peer, and required UDP ports
(43827, 43828, and 43829 on the sharing device). Keep the firewall enabled.

## Connect with a code

1. Extract the preview into a separate folder on each device. Do not copy an
   existing `.spectrum` folder between devices.
2. On the device that will share a window, open
   `spectrum-window-agent.exe`. It displays a six-digit code.
3. On the device that will view the window, open
   `spectrum-window-client.exe`. Choose the discovered device, enter the code
   shown on the sharing device, and select **Pair**.
4. On the sharing device, choose **Yes** to share the built-in test window.
   Choose **No** to select an application window, or **Cancel** to stop.
5. The viewer opens when the sharing device is ready. Close the viewer or the
   sharing window to end the session.

The code expires after two minutes and permits one connection attempt. If pairing
fails, close the programs and start again to obtain a new code. The code is used
only for that pairing attempt; it is not the long-term identity key. Do not send
a code to anyone who is not authorized to pair.

Identity keys are protected using the current Windows account. Each device
retains one paired peer; replacing a different peer requires explicitly unpairing
first. Temporary pairing certificates are not saved as device identities.

The discovery announcement contains no window title, host name, hardware
identifier, or certificate. Devices found by discovery remain untrusted until
the short-code exchange succeeds. A successful pairing is followed by a separate
mutually authenticated, hybrid-only TLS 1.3 connection for window viewing.

The selected image can contain visible title-bar text. The local chooser's list
of other window titles is not sent. Closing, minimizing, resizing, or invalidating
the selected window stops sharing; it never falls back to the desktop. Unknown
active owned popups stop the selected-window path.

## Local check and unpairing

In PowerShell, from the folder containing the executables, run on either device:

```powershell
.\spectrum-window-client.exe self-check
```

The local check does not create an identity or open a connection. To revoke the
saved peer on a device, run the matching command from the same folder:

```powershell
.\spectrum-window-agent.exe identity unpair
.\spectrum-window-client.exe identity unpair
```

Run only the command for the role used on that device. Active window sessions
stop when revocation is detected. Keep the `.spectrum` directories private and
do not share them when reporting a problem.

## Troubleshooting

The sharing and viewing programs show an error code when a step fails. Include
the code and the affected role when asking for help. The sharing device can run
`spectrum-window-check.exe` to check identity protection and capture of a
built-in test window. The check does not open a network connection, inspect
other application windows, or read or change saved pairing identities.

The check does not test device discovery, network ports, or a session between
devices. Keep pairing codes, identity files, and unrelated window contents
private when reporting a result.

## Build

Building from source requires Rust, Microsoft C++ build tools, and a Protobuf
compiler. Set `PROTOC` to the compiler executable if it is not on the current
process's `PATH`.

```powershell
cargo build --release --locked --bin spectrum-window-agent --bin spectrum-window-client --bin spectrum-window-check
```

For a portable Windows build, enable `-C target-feature=+crt-static` in
`RUSTFLAGS` for the build process. Windows graphics and data-protection
components are still required.
