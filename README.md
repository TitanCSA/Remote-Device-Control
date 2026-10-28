# Remote Device Control - direct Windows remote desktop

A portable C++ viewer and a single-file host installer. The host uses **[Sunshine](https://github.com/LizardByte/Sunshine)** for desktop capture/encoding and **[Vdevice](https://github.com/TitanCSA/Vdevice)** for real virtual USB keyboard and mouse input. The viewer uses **[moonlight-common-c](https://github.com/moonlight-stream/moonlight-common-c)** for GameStream transport.

**[Download](https://github.com/TitanCSA/Remote-Device-Control/releases/latest)** | [Architecture](docs/ARCHITECTURE.md) | [Validation and limits](docs/VALIDATION.md)

![Viewer preview in the test VM; no connection active](docs/viewer-preview.png)

## Install and connect

**Target PC**

1. Run `RemoteDeviceControlSetup.exe` as administrator and choose **Install / repair**. It installs the host engine, one automatic service, and the unchanged Microsoft-signed Vdevice demo when needed.
2. Keep code protection, or choose code-free access with local approval. Restart Windows only if requested, then sign in and keep the console desktop unlocked.
3. For protected access, copy the connection code and share it privately. Code-free hosts appear in the viewer's **local network** list.

**Controlling PC**

1. Run `RemoteDeviceControl.exe`. No installation, driver or administrator rights are needed here.
2. Select a local PC, paste its private connection code, or enter its IP address / DNS name for code-free access. Confirm the target certificate when connecting to a new manually entered address.
3. Click the remote desktop to control it. **Ctrl+Alt+F12** releases capture; **F11** toggles full screen. Disconnect releases held keys/buttons and removes the session's virtual devices.

There is one pending or active controller per target. In approval mode, each connection must be accepted on the target within 25 seconds. The target has a visible tray indicator with a command to disconnect and pause access for 30 seconds.

**Code-free access without local approval allows anyone who can reach the host to control its unlocked desktop.** Use a private code or retain approval on untrusted networks. Keep the private connection code secret.

## Direct LAN and Internet

There is **no central relay, account server or Internet PC directory**. Desktop and input travel directly between the two PCs using Sunshine/Moonlight's GameStream streaming stack. The old relay and directory are no longer used.

LAN discovery uses UDP **48762** on Private/Domain interfaces and local subnets. Only explicitly code-free hosts are advertised. Private hosts remain unlisted.

For Internet access, enable **Direct Internet / UPnP** on the target and connect using its reachable public IP or DNS name. UPnP must be supported and allowed by the router; otherwise forward the required ports manually. CGNAT, double NAT and restrictive firewalls can prevent direct access. There is no automatic relay fallback. A private code has the form `RDC3;HOST;...`: for Internet access, replace only `HOST` with the reachable public IP/DNS name; keep the certificate pin and other fields unchanged. Existing relay-enabled installations migrate to LAN-only until direct Internet access is explicitly enabled.

| Host port | Purpose |
| --- | --- |
| TCP 48784 | HTTPS authorization and GameStream control |
| TCP 48789 | GameStream HTTP service information |
| TCP 48810 | RTSP stream setup |
| UDP 48798, 48799, 48800, 48802 | GameStream video, encrypted control/input and protocol media ports |
| UDP 48762 | Local discovery only; do not forward this port |

The default firewall policy restricts access to Private/Domain local subnets. Internet access is a separate administrator choice. The Sunshine configuration website and legacy PIN-pairing endpoints are disabled in this managed host. The initial authorization is specific to this application; it is not a promise that an unmodified Moonlight application can pair with it.

## Performance and scope

Sunshine captures the desktop and selects a supported hardware H.264 encoder (NVENC, AMF or Intel Quick Sync), with software fallback. The viewer receives RTP/UDP video through Moonlight's loss recovery and decodes H.264 with Windows Media Foundation. Hardware decoding is used when available. A dedicated pull-renderer thread consumes complete access units, and the UI displays the latest decoded frame.

Keyboard and mouse use GameStream's encrypted control/input channel, separately from the video stream. The host submits raw HID reports through Vdevice: an NKRO keyboard, an absolute desktop mouse and a relative mouse. It does not fall back to Windows `SendInput`.

Hardware capabilities, display refresh, encoding, decoding, frame presentation, Windows scheduling and the network still determine latency. The displayed control RTT measures a network round trip; it is not an input-to-photon or game-reaction measurement. The current renderer converts decoded output to CPU BGRA before Direct2D presentation; it is not a zero-copy GPU renderer.

Supported scope: Windows 10 2004+ / Windows 11 **x64**, active signed-in unlocked console desktop, SDR H.264 up to 1920 x 1080. Audio, clipboard/file transfer, controller forwarding and secure-desktop control are not implemented. Locking/logging out ends sharing. The viewer refuses its own locally installed host to prevent an input feedback loop.

## Vdevice demo and removal

The included **Microsoft-signed Vdevice 1.0.5.0 demo** allows **one hour per Windows kernel boot**, shared with other Vdevice applications, starting with the first virtual-device creation. Expiry stops control. Closing/reinstalling does not reset it; use Windows **Restart** for a new allowance. Microsoft signing covers the upstream kernel package, not these application EXEs.

Open setup or **Windows Settings > Apps > Remote Device Control**, then choose **Uninstall**. The host, owned engine, service, firewall rules, settings and registration are removed. A preexisting/shared Vdevice installation is preserved; removing an app-installed driver is optional and can require a restart. Unexpected files are retained and reported. Windows event/security/SetupAPI records remain.

## Build

Install Visual Studio 2022 Desktop C++, a Windows SDK, CMake, Python 3.9+ and Git. Fetch the exact pinned viewer dependencies and build:

```powershell
python Tools/Prepare-Moonlight.py
.\Build.ps1 -TestsOnly
.\Build.ps1
```

A plain source build produces the portable viewer and host wrapper. Building the single-file installer additionally requires the matching unchanged [Vdevice 1.0.5.0 console setup](https://github.com/TitanCSA/Vdevice/releases) and the Sunshine engine cabinet/manifest:

```powershell
.\Build.ps1 -VdeviceSetup C:\Downloads\VdeviceSetupConsole.exe `
  -EngineCab C:\Build\Engine.cab -EngineManifest C:\Build\Engine.manifest
```

See [the engine integration and reproducible source instructions](ThirdParty/Sunshine/README.md). Application code, Vdevice's raw two-file SDK, upstream pins and integration patches are included. **Vdevice kernel source and signing secrets are excluded.**

The combined application is distributed under **GPL-3.0**, with retained upstream MIT/BSD/Apache notices in `licenses/`. The independently supplied Vdevice driver has separate demo binary terms. Use only on computers whose owner has authorized remote control. The software is provided as-is, without a zero-latency, universal-compatibility or bug-free guarantee.
