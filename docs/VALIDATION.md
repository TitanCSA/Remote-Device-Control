# Validation and limits - 0.3.0

Validation was performed on 28 October 2026. These checks establish the behavior exercised below; they do not prove zero latency, absence of every vulnerability, or compatibility with every PC, GPU, game or router.

## Native builds and offline checks

The x64 MSVC Release build and a separate AddressSanitizer build pass all seven native suites. A clean public-source build also passes without an installer payload, private test helpers or driver installation.

| Suite | Coverage |
| --- | --- |
| Core | Actual localhost pinned TLS, identity persistence, bounded configuration/input values, DNS connection, credential-free certificate probe and cancellation of blocked reads |
| Input | Raw keyboard/mouse descriptors and state, scan mapping, owned-device readiness argument bounds |
| Discovery | Nonces, bounded packets/lists, UTF-8, subnet restrictions and expiry |
| Setup | Ownership, command-line quoting, legacy configuration migration, direct firewall plans and LAN defaults |
| GameStream | HTTP/XML/JSON bounds and error details, real Sunshine version syntax, key mapping, lifecycle and the exact compiled AES-GCM implementation |
| Codec | Actual synthetic H.264 encode/decode on hardware and forced software paths, orientation/color/crop, padded1080p, malformed data and decoder thread ownership |
| Engine bundle | Actual in-memory cabinet extraction/validation, sizes, hashes, safe paths, duplicate/prefix collisions and manifest limits |

The crypto test includes eight concurrent workers, each creating 1,000 independent AES-GCM encrypt/decrypt pairs, plus in-place payload lengths0 through128 and altered authentication tags. The managed engine's separate C++ checks cover200,480 input/control/key-map boundary and randomized cases. These are protocol/parser tests, not a claim that hundreds of thousands of physical devices were tested.

The upstream engine source and all local production modifications are pinned and reproducible through `ThirdParty/Sunshine`. The release includes corresponding user-mode source and dependency notices. Vdevice's unchanged signed driver package is embedded by exact hash; no kernel change was made for this release.

## Actual disposable-VM qualification

The target was an isolated Windows11 x64 VM with Secure Boot, two virtual CPUs and an interactive console. The original development VMs/base disks were not changed. The target used software H.264 encoding; the controlling workstation used Media Foundation/D3D11 decoding and GPU color conversion with BGRA readback.

Executed checks:

- Single-file setup self-check, install and repeated repair passed. The existing shared Vdevice installation was preserved.
- The actual Sunshine/Moonlight encrypted GameStream session received1920 x1080 video. A representative immediate-input run connected in1,016ms and decoded its first frame in1,204ms, including authorization, virtual-device creation and stream setup.
- Immediately after that first frame, without an added warmup, Windows Raw Input/application messages recorded a key down/up, one application key press, one left click, one wheel notch and pointer motion. Held key/button state was zero after disconnect.
- A second controller was refused while the first continued receiving video for20 seconds.
- An incorrect certificate pin was refused before HTTP; an incorrect access code returned HTTP403. Fresh unregistered client certificates received GameStream XML status401 for protected application-list/cancel requests. HTTP200 with XML401 is the protocol's application-level denial, not an accepted request.
- In code-free approval mode, choosing No on the target produced an explicit403 with the local refusal/timeout explanation and no stream. Choosing Yes subsequently started the encrypted video session.
- Locking Windows ended sharing; the engine and all owned input devices disappeared while the automatic wrapper service stayed running. Unlocking restarted the engine.
- The normal-user viewer preview opened correctly in the VM; F11 filled the1024 x768 monitor, restored the original window bounds and closed cleanly. Offscreen native checks also covered1280 x820 and840 x520 toolbar/sidebar geometry.
- Uninstall returned success and removed the program/state directories, host service, Apps entry, identity registration and firewall rules. No engine process remained; the preexisting shared Vdevice installation kept running. Windows audit/history was preserved.
- A deliberately unrecognized legacy test file was retained and reported during engine repair; the installer did not delete it as owned engine data.

The software-encoded VM reported roughly32 decoded FPS and1ms control-network RTT in these runs. This is a functional test environment, **not a physical-PC performance benchmark**. First-frame startup time and network RTT are not mouse-to-game, key-to-application or input-to-photon latency measurements. The current renderer includes GPU-to-CPU readback and a later Direct2D upload; it is not zero-copy.

## Network and deployment scope

The old dedicated relay/directory service, its routes and runtime were removed. Its endpoints return404 and its old loopback port is closed; the separate website and licensing service remain available. The new application contains no central relay, Internet directory, licensing request or fallback path.

Direct Internet/UPnP and router/NAT behavior have not been qualified across physical routers, CGNAT, IPv6 providers or remote WANs. A reachable address and permitted inbound GameStream ports are required. Private/Domain LAN rules and code protection are defaults; Internet exposure and code-free access are separate administrator choices.

Windows10/11 x64 is the intended platform, but the end-to-end VM run above was Windows11. Hardware encoders, different GPUs, HDR, protected video and every Windows installation are not universally qualified. The supported media scope is SDR H.264, primary interactive unlocked console, up to1920 x1080. Audio, controller forwarding, clipboard/file transfer and secure-desktop sharing are outside this version.

The Vdevice demo remains one hour per Windows kernel boot. Closing or reinstalling this app does not reset it. Uninstall preserves shared Vdevice and Windows' own audit/security/SetupAPI records. Unknown files are retained and reported rather than deleted.
