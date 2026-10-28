# Validation and practical limits

Validation performed on 28 October 2026. This is an initial release, not a guarantee for every PC, network, application or graphics driver.

## Automated checks

- Release builds use Windows x64, C++17, static MSVC runtime, `/W4 /WX`, Control Flow Guard, ASLR and DEP. Four native test suites pass.
- Core: 71,886 assertions covering pinned TLS, identity persistence, bounded messages, credentials, protocol validation and relay video pacing under a simulated producer load.
- Input: 131,359 assertions covering both HID descriptors, report encoding, key modifiers, mouse coordinates, transitions and invalid inputs.
- Capture: 257 checks covering bounded JPEG decoding, malformed data, dimensions and encode/decode round trips.
- Installer: 34 checks covering command parsing and ownership checks. The embedded Vdevice setup, host and removal helper are checked against the exact build inputs.
- Core, input and image tests also pass with AddressSanitizer using MSVC 14.44.35207 and its matching runtime. This covers these user-mode tests, not arbitrary kernel or graphics stacks.
- The relay has 17 automated tests. Native Internet fixtures additionally exercise independent input/video channels, large transfers, refused tokens, peer disconnect and cancellation of pending connections.
- A public-source-only checkout builds without private laboratory helpers or driver source. Building the complete installer additionally requires the documented upstream Vdevice console setup.

## Windows VM checks

The live target is an isolated Windows 11 x64 Hyper-V VM with Secure Boot enabled and the unchanged Microsoft-signed Vdevice demo. The physical workstation was not used as an input-injection target.

Fresh installation and repair succeed. The host service starts after a normal Windows restart. Real desktop frames are received through both direct LAN and the public HTTPS relay. A separate foreground application confirms a key press, mouse click, wheel notch and expected absolute pointer position. Raw Input also confirms keyboard and mouse traffic.

The viewer's labelled offline preview was also checked in the interactive VM. F11 expands it to the monitor bounds, a second F11 restores the original bounds, and closing exits successfully. The README image is this offline preview, not a fabricated active connection.

Sequential LAN/relay reconnects pass. Deliberately disconnecting while a key and mouse button are held leaves neither held, removes the owned virtual HID devices and terminates the capture helper. Locking Windows likewise removes those devices and leaves only the idle host service.

Owned-package uninstall was exercised through its requested normal restart and final cleanup. Windows then reports no host/Vdevice services, own firewall rule, configuration, Apps registration or owned application directory. Windows audit and setup logs are intentionally retained.

The shared-driver case also passes: keeping Vdevice during removal, reinstalling the host over that existing driver, then uninstalling again preserves Vdevice while removing the host's files, service and configuration.

The laboratory base contained obsolete third-party keyboard/mouse mapper packages. They prevented Windows from starting the virtual HID children even though USB enumeration succeeded. Removing those packages in the disposable VM restored input. The application now checks its exact owned HID class children during startup and reports their PnP problem/service if they fail; it does not remove other drivers.

Observed input acknowledgement round trips were approximately **1 ms over the virtual LAN** and **43 ms through the Internet relay** during these runs. These are individual environment-specific observations, not guaranteed percentiles or input-to-display measurements. An acknowledgement means the host accepted the reports; receiving applications and display refresh add further delay.

An independent synthetic 720p image benchmark observed JPEG encoding around 1.9 ms and decoding around 1.7 ms at the median on the development PC. It does not measure real desktop capture, a GPU pipeline or total remote-control latency.

## Scope

Only an unlocked, signed-in primary console desktop is shared. Locking, logging out, changing to a secure desktop or losing the capture helper ends the session. UAC secure-desktop control, the Windows sign-in screen, multi-monitor selection, audio, clipboard and file transfer are not implemented.

Screen encoding currently uses CPU JPEG with DXGI capture or a GDI fallback. It is suitable for desktop control and debugging; hardware video encoding and a controlled physical input-to-photon measurement remain future work. Frame rate and bandwidth depend on screen activity, resolution, CPU and network conditions.

Relay video is paced below the server's bandwidth allowance. The sender waits before selecting the newest frame, keeping obsolete captures out of an accumulating network queue. LAN video has no added pacing; input has a separate connection and bandwidth budget.

Windows 10 2004+ is a build target. The live installation/control test described here used Windows 11; other Windows builds and physical GPU/network combinations still need field testing. The public relay is bounded and best-effort, and is not a high-availability service.

The Vdevice demo's shared one-hour allowance remains enforced by its existing driver. No new kernel binary was built or modified for this application.
