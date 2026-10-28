#pragma once
#include "Transport.h"
#include <memory>
#include <functional>
#include <string_view>

namespace RemoteControl {
// Outer HTTPS is validated by Windows. The caller establishes its separate
// end-to-end pinned TLS session through the returned ciphertext byte stream.
// Exactly one reader and one writer may run concurrently. Close cancels pending
// asynchronous WinHTTP I/O; join those caller threads before destroying it.
// OpenRelay waits at most20s for its peer after the bounded HTTPS upgrade.
// The optional thread-safe predicate is checked at least every100ms while
// waiting, including initial peer pairing, so service shutdown need not wait20s.
std::unique_ptr<TitanTransport::ByteStream> OpenRelay(
    std::wstring_view wssUrl,std::string_view room,std::string_view token,
    std::string_view role,std::string_view channel,std::function<bool()> cancelled={},std::string_view hostKey={});
}
