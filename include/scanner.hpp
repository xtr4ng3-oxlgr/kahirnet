#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "services.hpp"

namespace kahirnet {

struct PortResult {
    uint16_t port = 0;
    std::string service;
    std::string exposure;
    std::string banner;
};

struct HostResult {
    std::string target;      // as given
    std::string address;     // resolved IP
    bool reachable = false;  // at least one open or closed port (host answered)
    std::vector<PortResult> open_ports;
};

struct Finding {
    std::string severity;
    std::string host;
    std::string title;
    std::string detail;
    std::string advice;
};

struct ScanConfig {
    std::vector<uint16_t> ports;
    int timeout_ms = 800;
    int threads = 64;
    bool banners = true;
};

struct ScanReport {
    std::string generated_at;
    int hosts_scanned = 0;
    int hosts_up = 0;
    int open_total = 0;
    uint32_t exposure_score = 0;
    std::string verdict;
    std::vector<HostResult> hosts;
    std::vector<Finding> findings;
};

// Expands a target specification into concrete hosts. Supports a single
// host/IP, a comma list, and simple IPv4 forms: "192.168.1.1-20" (last
// octet range) and "192.168.1.0/24" (CIDR, capped to a sane size).
std::vector<std::string> expand_targets(const std::string& spec, std::string& error);

// Parses a port specification: "80", "1-1024", "22,80,443", "top" for a
// built-in common set, or "1-65535". Ranges are validated and bounded.
std::vector<uint16_t> parse_ports(const std::string& spec, std::string& error);

std::vector<uint16_t> top_ports();

ScanReport run_scan(const std::vector<std::string>& hosts, const ScanConfig& config);

}  // namespace kahirnet
