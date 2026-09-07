#include "scanner.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <ctime>
#include <mutex>
#include <sstream>
#include <thread>

#include "net.hpp"

namespace kahirnet {

namespace {

// A CIDR wider than /22 (1024 addresses) is almost always a mistake at
// the command line and would turn a quick check into a very long scan.
// The ceiling is a guardrail, not a technical limit; larger ranges can
// be scanned by naming narrower blocks deliberately.
constexpr uint32_t kMaxCidrHosts = 1024;
constexpr std::size_t kMaxPorts = 65535;

bool parse_ipv4(const std::string& text, uint32_t& out) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    char extra = 0;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) {
        return false;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return false;
    }
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

std::string ipv4_to_string(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.' << ((ip >> 16) & 0xFF) << '.' << ((ip >> 8) & 0xFF) << '.'
        << (ip & 0xFF);
    return oss.str();
}

std::vector<std::string> split(const std::string& text, char delim) {
    std::vector<std::string> parts;
    std::string current;
    std::istringstream stream(text);
    while (std::getline(stream, current, delim)) {
        if (!current.empty()) {
            parts.push_back(current);
        }
    }
    return parts;
}

std::string now_iso() {
    const std::time_t now = std::time(nullptr);
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &now);
#else
    gmtime_r(&now, &tm_buf);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buffer);
}

}  // namespace

std::vector<uint16_t> top_ports() {
    return {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445, 554, 587,
            993, 995, 1433, 1521, 1883, 2323, 3306, 3389, 5432, 5900, 6379, 8080,
            8443, 9200, 27017};
}

std::vector<std::string> expand_targets(const std::string& spec, std::string& error) {
    std::vector<std::string> result;

    for (const auto& token : split(spec, ',')) {
        // CIDR form
        const auto slash = token.find('/');
        if (slash != std::string::npos) {
            const std::string base = token.substr(0, slash);
            uint32_t prefix = 0;
            try {
                prefix = static_cast<uint32_t>(std::stoul(token.substr(slash + 1)));
            } catch (...) {
                error = "Invalid CIDR prefix in: " + token;
                return {};
            }
            uint32_t base_ip = 0;
            if (!parse_ipv4(base, base_ip) || prefix > 32) {
                error = "Invalid CIDR: " + token;
                return {};
            }
            const uint32_t host_bits = 32 - prefix;
            const uint64_t count = (host_bits >= 32) ? (1ull << 32) : (1ull << host_bits);
            if (count > kMaxCidrHosts) {
                error = "Range too large (" + std::to_string(count) +
                        " hosts). Use /22 or narrower, or name smaller blocks.";
                return {};
            }
            const uint32_t mask = (host_bits >= 32) ? 0 : (0xFFFFFFFFu << host_bits);
            const uint32_t network = base_ip & mask;
            for (uint64_t i = 0; i < count; ++i) {
                result.push_back(ipv4_to_string(network + static_cast<uint32_t>(i)));
            }
            continue;
        }

        // Last-octet range form: a.b.c.X-Y
        const auto dash = token.find('-');
        if (dash != std::string::npos) {
            const auto last_dot = token.rfind('.', dash);
            if (last_dot != std::string::npos) {
                const std::string prefix = token.substr(0, last_dot + 1);
                const std::string start_s = token.substr(last_dot + 1, dash - last_dot - 1);
                const std::string end_s = token.substr(dash + 1);
                try {
                    const int start = std::stoi(start_s);
                    const int end = std::stoi(end_s);
                    if (start >= 0 && end <= 255 && start <= end) {
                        uint32_t check = 0;
                        if (parse_ipv4(prefix + start_s, check)) {
                            for (int i = start; i <= end; ++i) {
                                result.push_back(prefix + std::to_string(i));
                            }
                            continue;
                        }
                    }
                } catch (...) {
                    // fall through to treat as literal
                }
            }
        }

        result.push_back(token);
    }

    if (result.empty()) {
        error = "No valid targets parsed from: " + spec;
    }
    return result;
}

std::vector<uint16_t> parse_ports(const std::string& spec, std::string& error) {
    if (spec == "top") {
        return top_ports();
    }

    std::vector<uint16_t> ports;
    for (const auto& token : split(spec, ',')) {
        const auto dash = token.find('-');
        if (dash != std::string::npos) {
            try {
                const long start = std::stol(token.substr(0, dash));
                const long end = std::stol(token.substr(dash + 1));
                if (start < 1 || end > 65535 || start > end) {
                    error = "Invalid port range: " + token;
                    return {};
                }
                for (long p = start; p <= end; ++p) {
                    ports.push_back(static_cast<uint16_t>(p));
                }
            } catch (...) {
                error = "Invalid port range: " + token;
                return {};
            }
        } else {
            try {
                const long p = std::stol(token);
                if (p < 1 || p > 65535) {
                    error = "Port out of range: " + token;
                    return {};
                }
                ports.push_back(static_cast<uint16_t>(p));
            } catch (...) {
                error = "Invalid port: " + token;
                return {};
            }
        }
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    if (ports.size() > kMaxPorts) {
        ports.resize(kMaxPorts);
    }
    if (ports.empty()) {
        error = "No valid ports parsed from: " + spec;
    }
    return ports;
}

namespace {

// Scans one host across all configured ports. A small worker pool splits
// the ports so a host with many ports doesn't scan serially; each thread
// walks a strided slice of the port list.
HostResult scan_host(const std::string& target, const ScanConfig& config) {
    HostResult host;
    host.target = target;
    host.address = resolve_display(target);

    std::mutex mutex;
    std::atomic<bool> any_answer{false};
    const int worker_count = std::max(1, std::min(config.threads, static_cast<int>(config.ports.size())));

    auto worker = [&](int index) {
        for (std::size_t i = static_cast<std::size_t>(index); i < config.ports.size();
             i += static_cast<std::size_t>(worker_count)) {
            const uint16_t port = config.ports[i];
            const ConnectResult rc = tcp_connect(target, port, config.timeout_ms);

            if (rc == ConnectResult::Open || rc == ConnectResult::Closed) {
                any_answer = true;
            }
            if (rc != ConnectResult::Open) {
                continue;
            }

            PortResult pr;
            pr.port = port;
            const ServiceInfo info = service_for_port(port);
            pr.service = info.name;
            pr.exposure = info.exposure;
            if (config.banners) {
                pr.banner = grab_banner(target, port, config.timeout_ms);
            }

            std::lock_guard<std::mutex> lock(mutex);
            host.open_ports.push_back(std::move(pr));
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(static_cast<std::size_t>(worker_count));
    for (int t = 0; t < worker_count; ++t) {
        pool.emplace_back(worker, t);
    }
    for (auto& t : pool) {
        t.join();
    }

    std::sort(host.open_ports.begin(), host.open_ports.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    host.reachable = any_answer.load() || !host.open_ports.empty();
    return host;
}

void synthesize_findings(ScanReport& report) {
    uint32_t score = 0;

    for (const auto& host : report.hosts) {
        for (const auto& port : host.open_ports) {
            const ServiceInfo info = service_for_port(port.port);
            if (info.exposure.empty()) {
                continue;
            }

            std::string severity = info.exposure;
            std::ostringstream title;
            title << info.name << " reachable on port " << port.port;

            std::string detail = info.note;
            if (!port.banner.empty()) {
                detail += " Banner: " + port.banner;
            }

            report.findings.push_back(Finding{severity, host.address, title.str(), detail, info.advice});

            if (severity == "high") {
                score += 20;
            } else if (severity == "medium") {
                score += 10;
            } else if (severity == "low") {
                score += 3;
            }
        }
    }

    report.exposure_score = std::min<uint32_t>(score, 100);
    if (report.exposure_score >= 60) {
        report.verdict = "high exposure";
    } else if (report.exposure_score >= 30) {
        report.verdict = "moderate exposure";
    } else if (report.exposure_score > 0) {
        report.verdict = "low exposure";
    } else {
        report.verdict = "no notable exposure";
    }
}

}  // namespace

ScanReport run_scan(const std::vector<std::string>& hosts, const ScanConfig& config) {
    ScanReport report;
    report.generated_at = now_iso();
    report.hosts_scanned = static_cast<int>(hosts.size());

    for (const auto& target : hosts) {
        HostResult host = scan_host(target, config);
        if (host.reachable) {
            ++report.hosts_up;
        }
        report.open_total += static_cast<int>(host.open_ports.size());
        report.hosts.push_back(std::move(host));
    }

    synthesize_findings(report);
    return report;
}

}  // namespace kahirnet
