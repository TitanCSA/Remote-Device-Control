#pragma once
#include <windows.h>
#include "src/platform/windows/keylayout.h"
namespace rdc {
// Private decoder-to-backend flag; kept in the upstream key-state identity too.
inline constexpr unsigned char ExtendedKeyFlag = 0x80;
struct KeyMapping { unsigned scan = 0; bool extended = false; unsigned usage = 0; };
inline KeyMapping MapKey(unsigned short key, unsigned char flags) {
    if (key == VK_PAUSE) return {0, false, 0x48};
    if (key == VK_SNAPSHOT) return {0, false, 0x46};
    bool extended = (flags & ExtendedKeyFlag) != 0;
    switch (key) {
        case VK_LWIN: case VK_RWIN: case VK_RMENU: case VK_RCONTROL:
        case VK_INSERT: case VK_DELETE: case VK_HOME: case VK_END:
        case VK_PRIOR: case VK_NEXT: case VK_UP: case VK_DOWN:
        case VK_LEFT: case VK_RIGHT: case VK_DIVIDE: case VK_APPS:
            extended = true; break;
        default: break;
    }
    // SS_KBE_FLAG_NON_NORMALIZED is bit 0; all ordinary native-viewer keys
    // use the stable US VK-to-scan table and the target's own keyboard layout.
    return {static_cast<unsigned>((flags & 1) ? MapVirtualKeyW(key, MAPVK_VK_TO_VSC) : platf::VK_TO_SCANCODE_MAP[key & 255]), extended, 0};
}
}
