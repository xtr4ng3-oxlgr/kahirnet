#include "net.hpp"

#include <cstring>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

namespace kahirnet {

namespace {

void close_socket(socket_t s) {
    if (s == kInvalidSocket) {
        return;
    }
#if defined(_WIN32)
    closesocket(s);
#else
    close(s);
#endif
}

bool set_nonblocking(socket_t s) {
#if defined(_WIN32)
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool connect_in_progress() {
#if defined(_WIN32)
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

// Waits until the socket becomes writable (connect finished) or the
// timeout expires. Returns 1 writable, 0 timeout, -1 error.
int wait_writable(socket_t s, int timeout_ms) {
    fd_set write_set;
    fd_set error_set;
    FD_ZERO(&write_set);
    FD_ZERO(&error_set);
    FD_SET(s, &write_set);
    FD_SET(s, &error_set);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

#if defined(_WIN32)
    const int nfds = 0;
#else
    const int nfds = static_cast<int>(s) + 1;
#endif
    const int ready = select(nfds, nullptr, &write_set, &error_set, &tv);
    if (ready <= 0) {
        return ready;  // 0 timeout, <0 error
    }
    if (FD_ISSET(s, &error_set)) {
        return -1;
    }
    return 1;
}

int wait_readable(socket_t s, int timeout_ms) {
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(s, &read_set);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

#if defined(_WIN32)
    const int nfds = 0;
#else
    const int nfds = static_cast<int>(s) + 1;
#endif
    return select(nfds, &read_set, nullptr, nullptr, &tv);
}

// Resolves host:port into a list of candidate addresses (v4 and v6),
// leaving the caller to try them. addrinfo is always freed.
struct AddrList {
    addrinfo* head = nullptr;
    ~AddrList() {
        if (head) {
            freeaddrinfo(head);
        }
    }
};

bool resolve(const std::string& host, uint16_t port, AddrList& out) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    std::snprintf(port_str, sizeof(port_str), "%u", static_cast<unsigned>(port));

    return getaddrinfo(host.c_str(), port_str, &hints, &out.head) == 0 && out.head != nullptr;
}

std::string sanitize_banner(const std::vector<char>& data, std::size_t length) {
    std::string out;
    out.reserve(length);
    std::size_t printable = 0;
    for (std::size_t i = 0; i < length && printable < 256; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\n' || c == '\r' || c == '\t') {
            if (!out.empty() && out.back() != ' ') {
                out += ' ';
            }
        } else if (c >= 0x20 && c < 0x7F) {
            out += static_cast<char>(c);
            ++printable;
        }
    }
    while (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

}  // namespace

bool net_startup(std::string& error) {
#if defined(_WIN32)
    WSADATA data;
    const int rc = WSAStartup(MAKEWORD(2, 2), &data);
    if (rc != 0) {
        error = "WSAStartup failed with code " + std::to_string(rc);
        return false;
    }
#else
    (void)error;
#endif
    return true;
}

void net_shutdown() {
#if defined(_WIN32)
    WSACleanup();
#endif
}

ConnectResult tcp_connect(const std::string& host, uint16_t port, int timeout_ms) {
    AddrList addrs;
    if (!resolve(host, port, addrs)) {
        return ConnectResult::Error;
    }

    bool saw_timeout = false;
    bool saw_refused = false;

    for (addrinfo* ai = addrs.head; ai != nullptr; ai = ai->ai_next) {
        socket_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == kInvalidSocket) {
            continue;
        }
        if (!set_nonblocking(s)) {
            close_socket(s);
            continue;
        }

        const int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (rc == 0) {
            close_socket(s);
            return ConnectResult::Open;
        }
        if (!connect_in_progress()) {
            close_socket(s);
            saw_refused = true;
            continue;
        }

        const int waited = wait_writable(s, timeout_ms);
        if (waited == 1) {
            // Writable: confirm there is no pending socket error, since a
            // refused connection can also report writable on some stacks.
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) == 0 &&
                so_error == 0) {
                close_socket(s);
                return ConnectResult::Open;
            }
            close_socket(s);
            saw_refused = true;
            continue;
        }

        close_socket(s);
        if (waited == 0) {
            saw_timeout = true;
        }
    }

    if (saw_refused) {
        return ConnectResult::Closed;
    }
    if (saw_timeout) {
        return ConnectResult::Filtered;
    }
    return ConnectResult::Error;
}

std::string grab_banner(const std::string& host, uint16_t port, int timeout_ms) {
    AddrList addrs;
    if (!resolve(host, port, addrs)) {
        return {};
    }

    for (addrinfo* ai = addrs.head; ai != nullptr; ai = ai->ai_next) {
        socket_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == kInvalidSocket) {
            continue;
        }
        if (!set_nonblocking(s)) {
            close_socket(s);
            continue;
        }

        const int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (rc != 0 && connect_in_progress()) {
            if (wait_writable(s, timeout_ms) != 1) {
                close_socket(s);
                continue;
            }
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) != 0 ||
                so_error != 0) {
                close_socket(s);
                continue;
            }
        } else if (rc != 0) {
            close_socket(s);
            continue;
        }

        // Some services announce themselves on connect (SSH, SMTP, FTP);
        // others (HTTP) stay silent until asked. A single benign,
        // read-oriented nudge is sent for the silent case. Nothing here
        // is an exploit or an attempt to do anything but read a greeting.
        if (port == 80 || port == 8080 || port == 8000 || port == 8888) {
            const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
            send(s, probe, static_cast<int>(std::strlen(probe)), 0);
        }

        if (wait_readable(s, timeout_ms) != 1) {
            close_socket(s);
            return {};
        }

        std::vector<char> buffer(1024);
        const int received =
            recv(s, buffer.data(), static_cast<int>(buffer.size()) - 1, 0);
        close_socket(s);

        if (received > 0) {
            return sanitize_banner(buffer, static_cast<std::size_t>(received));
        }
        return {};
    }

    return {};
}

std::string resolve_display(const std::string& host) {
    AddrList addrs;
    if (!resolve(host, 0, addrs)) {
        return host;
    }
    char buffer[INET6_ADDRSTRLEN] = {0};
    for (addrinfo* ai = addrs.head; ai != nullptr; ai = ai->ai_next) {
        void* addr_ptr = nullptr;
        if (ai->ai_family == AF_INET) {
            addr_ptr = &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            addr_ptr = &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr;
        }
        if (addr_ptr && inet_ntop(ai->ai_family, addr_ptr, buffer, sizeof(buffer))) {
            return std::string(buffer);
        }
    }
    return host;
}

}  // namespace kahirnet
