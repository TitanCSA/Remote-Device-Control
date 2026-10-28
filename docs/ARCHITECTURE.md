# Architecture

The target installs one `RemoteDeviceControlHost` LocalSystem service and the existing Vdevice demo. The portable viewer installs nothing.

An administrator configures the host using the installer. Its identity and three separate random capabilities are stored under SYSTEM/Administrators-only ACLs with Windows DPAPI machine protection. The installation directory allows normal users to read/execute the capture helper while preventing them from replacing its code. The random public room identifier is not a hardware fingerprint.

After pinned TLS and the private connection secret are checked, the service creates one NKRO HID keyboard and one absolute HID mouse. It starts its own protected executable under the active console user's token as an interactive capture helper. Session-0 services cannot directly capture a normal user's desktop. A unique local pipe accepts only the exact launched PID/session, rejects remote clients, and carries bounded frames/status. The helper receives no driver handle or privileged command interface.

The input channel grants a fresh session token. A second authenticated video channel must bind that token before receiving frames. Input messages are bounded, validated before application and strictly sequenced. Only obsolete pointer motion is coalesced. On disconnect, capture loss, lock/session change, expiry or input failure, held input is neutralized and the owned devices are removed.

For Internet access each channel runs inside an outbound HTTPS WebSocket. The relay capability is separate from the end-to-end connection secret. The relay pairs one host and one viewer per room/channel and passes opaque TLS bytes. It has bounded rooms, tasks, messages, lifetimes and rate limits. It does not record screens/keys or persist client IP histories. A public anonymous relay remains susceptible to bounded resource exhaustion; it is not an enterprise enrollment or billing system.

The capture, encode and transmit paths do not form an accumulating frame queue. The service replaces the latest frame waiting for video transmission. The viewer likewise retains the latest decoded frame for presentation. Separate control/video streams keep video backpressure out of input delivery.

Useful Windows documentation: [Desktop Duplication](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api), [interactive services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services), [WTSQueryUserToken](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken), [Vdevice](https://github.com/TitanCSA/Vdevice).
