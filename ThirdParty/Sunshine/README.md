# Managed Sunshine streaming engine

Remote Device Control uses the actual [Sunshine](https://github.com/LizardByte/Sunshine) GameStream host pipeline and a native client built on [moonlight-common-c](https://github.com/moonlight-stream/moonlight-common-c). Video uses Sunshine's Windows capture, hardware H.264 encoding when available, software encoding fallback, UDP/FEC and the GameStream control protocol. Keyboard and mouse use the separately installed Vdevice driver. No ViGEm, libvirtualhid or extra input driver is included.

The host is pinned to Sunshine **v2025.924.154138**, commit `86188d47a7463b0f73b35de18a628353adeaa20e`. This Windows 10/11 baseline has local modifications and later security backports; it is not an unmodified upstream release. The configuration web server and original PIN-pairing routes are disabled. The native viewer uses this application's certificate authorization and local approval before starting a normal GameStream session. Unmodified Moonlight pairing is therefore not supported.

## Build

Install Git for Windows, Python 3 and MSYS2 base tools. The script downloads a SHA256-pinned UCRT64 compiler/dependency set into its own `obj` directory; it does not install global packages or run the engine, capture a desktop, inject inputs or install a service.

```powershell
./ThirdParty/Sunshine/Build.ps1 -Python python.exe -Jobs 3
./Tools/Pack-Engine.ps1 -EngineDirectory ./obj/Payload/Engine
```

Use `-MsysDirectory` if MSYS2 is not in `C:\msys64`, or `-WorkDirectory` for another build directory. `MsysPackages.json` records all 48 dependency URLs, versions and SHA256 values. `SourcePins.json` records the source revisions. `Apply.py` refuses another Sunshine revision and applies only its pinned contexts. It replaces Windows input with `RdcVdevice.cpp`, backed by `Source/VirtualInput.cpp` and the public Vdevice SDK. It also supplies a headless tray stub and routes all mutable engine files to the wrapper's protected state directory.

The resulting `obj/Payload/Engine` contains the engine and real shader/image files. The tested build links dependencies statically and imports only Windows system DLLs. Its working directory must be the engine directory. The original upstream installer, web assets and gamepad driver installer are not packaged. Copy the dependency notices described below with the engine.

`ValidationTests.cpp` is compiled and run by the build script. It performs 200,480 offline checks of valid, truncated, oversized, unknown and randomized input packets, encrypted control/inner-header bounds, keypad Enter, Print Screen and modifier mapping, without opening a driver or starting capture. This complements, rather than replaces, actual streaming and device lifecycle tests.

## Supervisor contract

Only the installed wrapper launches the engine, as SYSTEM in the active, unlocked console session. Its environment supplies:

| Variable | Meaning |
| --- | --- |
| `RDC_STATE_DIR` | Required absolute protected engine state directory. |
| `RDC_ACCESS_SECRET` | 32 hexadecimal characters for private authorization. |
| `RDC_NO_CODE` | `1` permits the intentionally public zero-secret pairing path; `0` requires the private secret. |
| `RDC_REQUIRE_APPROVAL` | `1` asks the console user before each public connection. |
| `RDC_STOP_EVENT` | Wrapper-created, SYSTEM-only named event for graceful shutdown. |
| `RDC_STATUS_FILE` | Protected absolute JSON status path; updated at most once per second. |

`POST /rdc-pair` accepts bounded JSON containing `certificate`, `secret` and `clientid`. The certificate is an RSA 2048–4096-bit client leaf. Later HTTPS requests require that exact registered leaf and TLS proof of its private key. Pairing alone does not create a virtual device. Each launch reserves the sole controller slot, checks the console desktop, optionally requests local approval, then creates the owned Vdevice keyboard, absolute pointer and relative mouse. Startup waits for the exact owned Windows Raw Input interfaces and consumption of a neutral keyboard/relative-mouse report; it does not use a fixed warmup delay or move the absolute pointer. Disconnect, expiry, lock or engine shutdown removes those devices. Another trusted public client cannot cancel an existing controller's session.

The wrapper forces encrypted LAN and WAN streaming, supplies only the sealed Desktop app, clears its owned paired-client file on engine restart and keeps UPnP off by default. No central relay, directory, activation service, update check or analytics service is needed. Direct Internet connections still require a reachable target address and the documented router/firewall configuration; CGNAT is not solved by this protocol alone.

## Security changes

The fork includes upstream fixes for certificate issuer validation (`888a6bb`), short ENet control packets (`82bccdf`) and input packet bounds (`1583e7c`). It additionally bounds the entire encrypted-control envelope before header/cipher access and verifies its authenticated inner length, requires an exact paired leaf, serializes the certificate registry, disables legacy PIN pairing and the privileged configuration web UI, validates exact input lengths and recognized types, and bounds pending input to 256 packets with one fair worker. Overflow ends the session rather than silently discarding a key-release transition. Input packet contents are not logged. Raw Unicode injection, gamepads, touch and pen are not exposed by this keyboard/mouse application.

References: [Sunshine security advisories](https://github.com/LizardByte/Sunshine/security/advisories), [certificate validation](https://github.com/LizardByte/Sunshine/security/advisories/GHSA-ph75-mgxh-mv57), [input bounds](https://github.com/LizardByte/Sunshine/security/advisories/GHSA-26q2-58j6-qmvv), [control packet bounds](https://github.com/LizardByte/Sunshine/security/advisories/GHSA-c428-87f8-rrv5). These changes and tests do not establish that every possible security flaw has been eliminated.

## Redistribution and corresponding source

Sunshine and moonlight-common-c are GPLv3 software. The application is distributed under GPLv3 with its original notices retained. Vdevice's user-mode SDK and separately supplied, signed kernel binary retain their own notices; this archive never contains kernel source. The proprietary kernel binary must not be described as part of the GPL engine's source.

The release must include the matching user-mode corresponding-source archive and the dependency notices, not only links to moving upstream branches. `SourceBundle.py` packages the modified pinned Sunshine tree, initialized source submodules, the adapter sources and local patch/build scripts. It also includes the matching codec build sources and patches, FFmpeg/x264/x265/SVT sources, and libiconv source plus the MSYS2 recipe/patches used for its static library. Original compressed Boost and JSON source archives fetched by CMake are included, as are the exact native viewer Moonlight/MbedTLS sources and their pins. It excludes `.git`, generated objects, prepared codec binaries for unrelated platforms, the unused upstream website template, AMF's unused third-party binary samples, private credentials, logs and customer data by construction.

`Build.ps1` runs `PrepareSources.ps1` and `CopyNotices.ps1` automatically. The first fetches the codec-source repository at `2851db101eeddae8f02489d48a52a4d83e6f7e7b` with its submodules into `obj/Upstream/SunshineCodecSources`. That build-source commit corresponds to the `c38829d6b8c35b64b3ff7a569f51978ed72c4292` prepared-library commit. It also fetches libiconv 1.18 source and its `f89ccd3564cceff9ed46d778c91f278381393c75` MSYS2 recipe/patch files into `obj/Upstream/LibiconvSource`; the source tarball hash is in `SourcePins.json`. The second copies dependency notices into the engine bundle. Neither script starts the engine.

```powershell
python ./ThirdParty/Sunshine/SourceBundle.py --project . --output ./bin/Remote-Device-Control-Streaming-Source.zip
```

From an extracted source archive, build the included modified tree with `-SourceDirectory ./CorrespondingSource/Sunshine`. The ordinary build command fetches the pinned toolchain and prepared codec libraries. To rebuild those libraries themselves, use the included `CorrespondingSource/CodecBuild/CMakeLists.txt`, codec submodules, `patches` and workflow recipes. The libiconv folder includes the exact `PKGBUILD`, patches, configure flags and original tarball for relinking a modified version.

Retain these licenses/notices with binary distributions: Sunshine GPLv3, moonlight-common-c GPLv3, FFmpeg GPL, x264/x265 GPL, SVT-AV1 BSD and patent notice, Boost Software License, ENet MIT, Simple-Web-Server MIT, libdisplaydevice MIT, OpenSSL Apache-2.0, curl's license, Opus BSD, miniupnpc BSD, ICU/Unicode, libiconv LGPL, NVIDIA/AMF header notices and GCC runtime exception. The isolated package tree contains the corresponding `share/licenses` files; the source archive retains upstream license files and copyright headers.
