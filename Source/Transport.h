#pragma once
#ifndef TITAN_NATIVE_PINNED_TLS_TRANSPORT_V1_INCLUDED
#define TITAN_NATIVE_PINNED_TLS_TRANSPORT_V1_INCLUDED
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// Native Windows TLS transport. One reader and one writer per channel; Close
// wakes blocked I/O. No certificate store, firewall or service is modified.
namespace TitanTransport {
class ByteStream {
public:
    virtual ~ByteStream()=default;
    virtual size_t ReadSome(void* bytes,size_t capacity,uint32_t timeoutMilliseconds)=0;
    virtual void WriteAll(const void* bytes,size_t count,uint32_t timeoutMilliseconds)=0;
    virtual void Close() noexcept=0;
};
class Runtime {
public: Runtime(); ~Runtime(); Runtime(const Runtime&)=delete;
};
class Identity {
    struct State; std::unique_ptr<State> state_;
    friend class Channel;
public:
    Identity(); ~Identity(); Identity(const Identity&)=delete;
    explicit Identity(const std::vector<uint8_t>& protectedPfxPlaintext);
    std::vector<uint8_t> Export() const;
    std::string Fingerprint() const;
    std::string CertificatePem() const;
};
class Channel {
    struct State; std::unique_ptr<State> state_;
public:
    // socket ownership transfers even when TLS authentication throws.
    // Two-phase form allows a controller to publish Close() before a potentially
    // blocking handshake. No application I/O is allowed before it succeeds.
    explicit Channel(SOCKET socket);
    explicit Channel(std::unique_ptr<ByteStream> stream);
    void HandshakeServer(Identity& server);
    void HandshakeClient(std::string_view expectedSha256);
    void HandshakeClient(std::string_view expectedSha256,Identity& clientIdentity);
    // First-contact inspection only: no application bytes may be sent on this
    // channel, and it is closed before the observed certificate is returned.
    std::string ProbeServerCertificate();
    Channel(SOCKET socket,Identity& server);
    Channel(SOCKET socket,std::string_view expectedSha256);
    ~Channel(); Channel(const Channel&)=delete;
    void Send(const void* bytes,size_t count);
    // The complete requested byte count has one absolute deadline. Activity
    // cannot keep an unauthenticated application message alive indefinitely.
    void Receive(void* bytes,size_t count,uint32_t timeoutMilliseconds=5000);
    void Close() noexcept;
};
SOCKET Listen(std::string_view numericIPv4,uint16_t port,uint16_t* actualPort=nullptr);
SOCKET Connect(std::string_view host,uint16_t port);
std::string RandomSecret(); // 128 random bits, hex; never logged by the SDK.
bool IsFingerprint(std::string_view value) noexcept;
bool IsSecret(std::string_view value) noexcept;
bool ConstantTimeEqual(std::string_view a,std::string_view b) noexcept;
}
#endif // TITAN_NATIVE_PINNED_TLS_TRANSPORT_V1_INCLUDED
