#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "net.hpp"
#include "scanner.hpp"

namespace fs = std::filesystem;

namespace kahirnet {
void print_console(const ScanReport& report);
bool write_json(const ScanReport& report, const std::string& path, std::string& error);
bool write_html(const ScanReport& report, const std::string& path, std::string& error);
}  // namespace kahirnet

namespace {

constexpr const char* kVersion = "1.0.0";

constexpr const char* kBanner = R"(
  ██╗  ██╗ █████╗ ██╗  ██╗██╗██████╗ ███╗   ██╗███████╗████████╗
  ██║ ██╔╝██╔══██╗██║  ██║██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
  █████╔╝ ███████║███████║██║██████╔╝██╔██╗ ██║█████╗     ██║
  ██╔═██╗ ██╔══██║██╔══██║██║██╔══██╗██║╚██╗██║██╔══╝     ██║
  ██║  ██╗██║  ██║██║  ██║██║██║  ██║██║ ╚████║███████╗    ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝    ╚═╝
  AUTHORIZED NETWORK RECON :: CONNECT ONLY, NO EXPLOITS :: BY.XTR4NG3
)";

void print_help() {
    std::cout << kBanner << "\n";
    std::cout << "KAHIRNET v" << kVersion << " - created by xtr4ng3\n\n";
    std::cout << "Usage:\n";
    std::cout << "  kahirnet <targets> [options] --yes-authorized\n\n";
    std::cout << "Targets:\n";
    std::cout << "  192.168.1.1              single host\n";
    std::cout << "  192.168.1.1-50           last-octet range\n";
    std::cout << "  192.168.1.0/24           CIDR block (up to /22)\n";
    std::cout << "  host1,host2,10.0.0.5     comma list\n\n";
    std::cout << "Options:\n";
    std::cout << "  --ports <spec>    top | 1-1024 | 22,80,443 (default: top)\n";
    std::cout << "  --timeout <ms>    per-port connect timeout (default: 800)\n";
    std::cout << "  --threads <n>     concurrent connects per host (default: 64)\n";
    std::cout << "  --no-banners      skip banner grabbing\n";
    std::cout << "  --report <dir>    write HTML and JSON (default: reports)\n";
    std::cout << "  --no-report       console only\n";
    std::cout << "  --yes-authorized  confirm you are authorized to scan these targets\n\n";
    std::cout << "KAHIRNET makes ordinary TCP connections, runs no exploits, and changes\n";
    std::cout << "nothing on the hosts it scans. Only scan networks you own or have\n";
    std::cout << "written permission to test.\n";
}

std::string timestamp_suffix() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
        print_help();
        return 0;
    }

    std::string target_spec;
    std::string port_spec = "top";
    std::string report_dir = "reports";
    int timeout_ms = 800;
    int threads = 64;
    bool banners = true;
    bool write_files = true;
    bool authorized = false;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--ports" && i + 1 < args.size()) {
            port_spec = args[++i];
        } else if (a == "--timeout" && i + 1 < args.size()) {
            timeout_ms = std::max(50, std::atoi(args[++i].c_str()));
        } else if (a == "--threads" && i + 1 < args.size()) {
            threads = std::max(1, std::min(256, std::atoi(args[++i].c_str())));
        } else if (a == "--no-banners") {
            banners = false;
        } else if (a == "--report" && i + 1 < args.size()) {
            report_dir = args[++i];
        } else if (a == "--no-report") {
            write_files = false;
        } else if (a == "--yes-authorized") {
            authorized = true;
        } else if (a.rfind("--", 0) == 0) {
            std::cerr << "[ERROR] Unknown option: " << a << "\n";
            return 1;
        } else if (target_spec.empty()) {
            target_spec = a;
        } else {
            std::cerr << "[ERROR] Unexpected argument: " << a << "\n";
            return 1;
        }
    }

    if (target_spec.empty()) {
        std::cerr << "[ERROR] No targets given.\n";
        return 1;
    }

    // Scanning even a benign host on a network you do not control can be
    // unlawful and is not the tool's purpose. The gate is deliberate
    // friction: the operator must state authorization every run, exactly
    // as WARDEN-11 requires before touching a web target.
    if (!authorized) {
        std::cerr << "[ERROR] Refusing to scan without --yes-authorized.\n";
        std::cerr << "        Only scan networks you own or have written permission to test.\n";
        return 1;
    }

    std::string error;
    const std::vector<std::string> hosts = kahirnet::expand_targets(target_spec, error);
    if (hosts.empty()) {
        std::cerr << "[ERROR] " << error << "\n";
        return 1;
    }

    kahirnet::ScanConfig config;
    config.ports = kahirnet::parse_ports(port_spec, error);
    if (config.ports.empty()) {
        std::cerr << "[ERROR] " << error << "\n";
        return 1;
    }
    config.timeout_ms = timeout_ms;
    config.threads = threads;
    config.banners = banners;

    if (!kahirnet::net_startup(error)) {
        std::cerr << "[ERROR] " << error << "\n";
        return 1;
    }

    std::cout << kBanner << "\n";
    std::cout << "scanning " << hosts.size() << " host(s) across " << config.ports.size()
              << " port(s)...\n";

    const kahirnet::ScanReport report = kahirnet::run_scan(hosts, config);
    kahirnet::net_shutdown();

    kahirnet::print_console(report);

    if (write_files) {
        std::error_code ec;
        fs::create_directories(report_dir, ec);
        if (ec) {
            std::cerr << "[ERROR] Cannot create report directory: " << report_dir << "\n";
            return 1;
        }
        const std::string base = report_dir + "/kahirnet_" + timestamp_suffix();
        if (!kahirnet::write_json(report, base + ".json", error) ||
            !kahirnet::write_html(report, base + ".html", error)) {
            std::cerr << "[ERROR] " << error << "\n";
            return 1;
        }
        std::cout << "\nreport JSON: " << base << ".json\n";
        std::cout << "report HTML: " << base << ".html\n";
    }

    return 0;
}
