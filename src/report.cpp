#include "scanner.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

namespace kahirnet {

namespace {

std::string escape_html(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c; break;
        }
    }
    return out;
}

// Banners and service names originate from the scanned host, i.e. from a
// third party, and are written into a JSON report other tools consume.
// They are escaped as untrusted data even though the scan is authorized.
std::string escape_json(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out << buf;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string verdict_color(const std::string& verdict) {
    if (verdict.rfind("high", 0) == 0) return "#ff5c7a";
    if (verdict.rfind("moderate", 0) == 0) return "#ffc14d";
    if (verdict.rfind("low", 0) == 0) return "#4dd6ff";
    return "#4dffc3";
}

}  // namespace

void print_console(const ScanReport& report) {
    std::cout << "\n================ KAHIRNET REPORT ================\n";
    std::cout << "generated : " << report.generated_at << "\n";
    std::cout << "hosts     : " << report.hosts_up << " up / " << report.hosts_scanned
              << " scanned\n";
    std::cout << "open ports: " << report.open_total << "\n";
    std::cout << "verdict   : " << report.verdict << " (" << report.exposure_score << "/100)\n";
    std::cout << "-------------------------------------------------\n";

    for (const auto& host : report.hosts) {
        if (host.open_ports.empty()) {
            continue;
        }
        std::cout << host.address;
        if (host.address != host.target) {
            std::cout << " (" << host.target << ")";
        }
        std::cout << "\n";
        for (const auto& port : host.open_ports) {
            std::cout << "  " << port.port << "/tcp  " << port.service;
            if (!port.exposure.empty()) {
                std::cout << "  [" << port.exposure << "]";
            }
            if (!port.banner.empty()) {
                std::cout << "  \"" << port.banner << "\"";
            }
            std::cout << "\n";
        }
    }

    if (!report.findings.empty()) {
        std::cout << "-------------------------------------------------\n";
        std::cout << "EXPOSURE NOTES\n";
        for (const auto& f : report.findings) {
            std::string sev = f.severity;
            for (auto& c : sev) {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            std::cout << "[" << sev << "] " << f.host << " :: " << f.title << "\n";
            std::cout << "  " << f.detail << "\n";
            if (!f.advice.empty()) {
                std::cout << "  -> " << f.advice << "\n";
            }
        }
    }
    std::cout << "=================================================\n";
}

bool write_json(const ScanReport& report, const std::string& path, std::string& error) {
    std::ofstream out(path);
    if (!out) {
        error = "Cannot write JSON: " + path;
        return false;
    }

    out << "{\n  \"tool\": \"KAHIRNET\",\n  \"author\": \"xtr4ng3\",\n";
    out << "  \"generated_at\": \"" << escape_json(report.generated_at) << "\",\n";
    out << "  \"hosts_scanned\": " << report.hosts_scanned << ",\n";
    out << "  \"hosts_up\": " << report.hosts_up << ",\n";
    out << "  \"open_total\": " << report.open_total << ",\n";
    out << "  \"exposure_score\": " << report.exposure_score << ",\n";
    out << "  \"verdict\": \"" << escape_json(report.verdict) << "\",\n";

    out << "  \"hosts\": [\n";
    for (std::size_t h = 0; h < report.hosts.size(); ++h) {
        const auto& host = report.hosts[h];
        out << "    {\"address\": \"" << escape_json(host.address) << "\", \"target\": \""
            << escape_json(host.target) << "\", \"reachable\": "
            << (host.reachable ? "true" : "false") << ", \"open_ports\": [";
        for (std::size_t p = 0; p < host.open_ports.size(); ++p) {
            const auto& port = host.open_ports[p];
            out << "{\"port\": " << port.port << ", \"service\": \"" << escape_json(port.service)
                << "\", \"exposure\": \"" << escape_json(port.exposure) << "\", \"banner\": \""
                << escape_json(port.banner) << "\"}";
            if (p + 1 < host.open_ports.size()) out << ", ";
        }
        out << "]}";
        if (h + 1 < report.hosts.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"findings\": [\n";
    for (std::size_t i = 0; i < report.findings.size(); ++i) {
        const auto& f = report.findings[i];
        out << "    {\"severity\": \"" << escape_json(f.severity) << "\", \"host\": \""
            << escape_json(f.host) << "\", \"title\": \"" << escape_json(f.title)
            << "\", \"detail\": \"" << escape_json(f.detail) << "\", \"advice\": \""
            << escape_json(f.advice) << "\"}";
        if (i + 1 < report.findings.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n}\n";
    return true;
}

bool write_html(const ScanReport& report, const std::string& path, std::string& error) {
    std::ofstream out(path);
    if (!out) {
        error = "Cannot write HTML: " + path;
        return false;
    }

    const std::string accent = verdict_color(report.verdict);

    out << "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
    out << "<title>KAHIRNET Report</title>\n<style>\n";
    out << "body{background:#050a14;color:#d6e6f2;font-family:Consolas,Segoe UI,Arial;padding:30px}\n";
    out << "h1,h2{color:#33c9ff;letter-spacing:1px}\n";
    out << ".card{background:#0a1424;border:1px solid #16324d;border-left:3px solid #33c9ff;"
           "border-radius:5px;padding:18px;margin:16px 0}\n";
    out << "table{width:100%;border-collapse:collapse;margin-top:10px}\n";
    out << "td,th{border-bottom:1px solid #12283d;padding:8px;text-align:left;vertical-align:top}\n";
    out << "th{color:#6fb8e0}\ncode{color:#9fe0ff}\n";
    out << ".score{font-size:52px;font-weight:800;color:" << accent << "}\n";
    out << ".small{color:#6b8299}\n";
    out << ".high{color:#ff5c7a}.medium{color:#ffc14d}.low{color:#4dd6ff}\n";
    out << "</style>\n</head>\n<body>\n";

    out << "<h1>KAHIRNET</h1>\n<p class=\"small\">Authorized local network reconnaissance &middot; "
           "xtr4ng3 &middot; "
        << escape_html(report.generated_at) << "</p>\n";

    out << "<div class=\"card\"><h2>Exposure</h2><div class=\"score\">" << report.exposure_score
        << "/100</div><p><b>" << escape_html(report.verdict) << "</b></p><p>" << report.hosts_up
        << " host(s) up of " << report.hosts_scanned << " scanned &middot; " << report.open_total
        << " open port(s)</p></div>\n";

    out << "<div class=\"card\"><h2>Exposure notes</h2><table>";
    out << "<tr><th>Severity</th><th>Host</th><th>Finding</th><th>Advice</th></tr>";
    for (const auto& f : report.findings) {
        out << "<tr><td class=\"" << escape_html(f.severity) << "\">" << escape_html(f.severity)
            << "</td><td>" << escape_html(f.host) << "</td><td><b>" << escape_html(f.title)
            << "</b><br>" << escape_html(f.detail) << "</td><td>" << escape_html(f.advice)
            << "</td></tr>";
    }
    out << "</table></div>\n";

    out << "<div class=\"card\"><h2>Open ports</h2><table>";
    out << "<tr><th>Host</th><th>Port</th><th>Service</th><th>Exposure</th><th>Banner</th></tr>";
    for (const auto& host : report.hosts) {
        for (const auto& port : host.open_ports) {
            out << "<tr><td>" << escape_html(host.address) << "</td><td>" << port.port
                << "</td><td>" << escape_html(port.service) << "</td><td>"
                << escape_html(port.exposure) << "</td><td><code>" << escape_html(port.banner)
                << "</code></td></tr>";
        }
    }
    out << "</table></div>\n";

    out << "<p class=\"small\">KAHIRNET performs standard TCP connections only. It runs no "
           "exploits and changes nothing on the hosts it scans. Use only on networks you are "
           "authorized to test.</p>\n";
    out << "</body></html>\n";
    return true;
}

}  // namespace kahirnet
