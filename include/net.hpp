#pragma once

#include <cstdint>
#include <string>

namespace kahirnet {

// Result of a single TCP connect attempt against one host:port.
enum class ConnectResult {
    Open,       // handshake completed
    Closed,     // refused (something answered, nothing listening)
    Filtered,   // timed out with no answer (firewall/drop, or host down)
    Error,      // local failure (bad address, no sockets available)
};

// Initializes the platform socket stack. On Windows this calls
// WSAStartup; on POSIX it is a no-op. Must be called once before any
// connect attempt, and shutdown() called once at the end. Kept explicit
// rather than hidden in a static initializer so startup failure is
// visible and handled, not swallowed.
bool net_startup(std::string& error);
void net_shutdown();

// Attempts a TCP connection to host:port, giving up after timeout_ms.
// A non-blocking connect plus a bounded wait is used instead of a
// blocking connect, because a blocking connect against a filtered port
// can hang for the operating system's full SYN-retry period (over a
// minute), which would make scanning any real range unusable.
ConnectResult tcp_connect(const std::string& host, uint16_t port, int timeout_ms);

// Attempts to read a service banner from an already-identified open
// port, within the timeout. For a few well-known protocols a small
// prompt is sent first (an HTTP HEAD, an empty line) because those
// services stay silent until spoken to. Returns the bytes received with
// non-printable characters stripped, or an empty string. Never sends
// anything protocol-specific beyond a benign, read-oriented probe.
std::string grab_banner(const std::string& host, uint16_t port, int timeout_ms);

// Resolves a hostname to a printable IP for display. Returns the input
// unchanged if it is already a literal address or cannot be resolved.
std::string resolve_display(const std::string& host);

}  // namespace kahirnet
