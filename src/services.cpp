#include "services.hpp"

#include <unordered_map>

namespace kahirnet {

ServiceInfo service_for_port(uint16_t port) {
    // The exposure ratings encode a defensive posture judgement, not a
    // claim that the specific service is vulnerable. Plaintext admin
    // protocols (Telnet, FTP), remote access (RDP, VNC), databases and
    // industrial/IoT panels are rated high/medium because finding them
    // reachable is itself the finding: they are meant to sit behind a
    // firewall or VPN, and an ordinary user usually does not realize one
    // is exposed until told in words they understand.
    static const std::unordered_map<uint16_t, ServiceInfo> table = {
        {21, {"FTP", "high",
              "File transfer that usually sends the password in plain text, readable by anyone on the path.",
              "Prefer SFTP/FTPS. If FTP isn't needed, turn it off."}},
        {22, {"SSH", "low",
              "Encrypted remote administration. Safe when kept updated and not using password-only logins.",
              "Use key-based login, disable root login, keep it patched."}},
        {23, {"Telnet", "high",
              "Remote administration with no encryption at all. Everything, including the password, travels in clear text.",
              "Telnet should not be exposed. Replace it with SSH and disable it."}},
        {25, {"SMTP", "medium",
              "Mail sending. An openly reachable mail server can be abused to relay spam.",
              "Confirm it isn't an open relay and is meant to be reachable."}},
        {53, {"DNS", "low",
              "Name resolution. Normal on a server; an open resolver can be abused for amplification attacks.",
              "If it's a public resolver, confirm that's intended."}},
        {110, {"POP3", "medium",
               "Mail retrieval, often unencrypted on this port.",
               "Prefer the encrypted variant (POP3S/995) or IMAP over TLS."}},
        {135, {"MSRPC", "high",
               "Windows internal service. Should never be reachable from outside the local network.",
               "Block at the firewall. Exposure here is a common entry point."}},
        {139, {"NetBIOS", "high",
               "Legacy Windows file/printer sharing. Should stay inside the local network only.",
               "Block at the perimeter; disable if unused."}},
        {143, {"IMAP", "medium",
               "Mail retrieval, sometimes unencrypted on this port.",
               "Prefer IMAP over TLS (993)."}},
        {445, {"SMB", "high",
               "Windows file sharing. A frequent target of worms and ransomware when exposed to the internet.",
               "Never expose SMB to the internet. Keep it on the local network behind a firewall."}},
        {1433, {"MSSQL", "high",
                "Microsoft SQL Server database. A database reachable from outside is a serious exposure.",
                "Put it behind a firewall/VPN. Databases should not face the internet."}},
        {1521, {"Oracle DB", "high",
                "Oracle database listener. Should not be directly reachable.",
                "Restrict to application servers behind a firewall."}},
        {3306, {"MySQL/MariaDB", "high",
                "Database server. Reachable databases are routinely scanned and attacked.",
                "Bind to localhost or restrict to trusted hosts; never expose publicly."}},
        {3389, {"RDP", "high",
                "Windows Remote Desktop. One of the most attacked services on the internet when exposed.",
                "Put it behind a VPN, never directly on the internet. Enable network-level authentication."}},
        {5432, {"PostgreSQL", "high",
                "Database server. Should not be publicly reachable.",
                "Bind to localhost or restrict by firewall."}},
        {5900, {"VNC", "high",
                "Remote screen sharing, historically weak on authentication.",
                "Tunnel over SSH/VPN; never expose VNC directly."}},
        {6379, {"Redis", "high",
                "In-memory database that traditionally ships with no authentication.",
                "Bind to localhost, enable auth. An open Redis is often full remote compromise."}},
        {27017, {"MongoDB", "high",
                 "Database server. Historically exposed with no authentication in default setups.",
                 "Enable authentication and firewall it. Open MongoDB has leaked many databases."}},
        {80, {"HTTP", "low",
              "Unencrypted web service. Normal, but the site itself should be reviewed for HTTPS.",
              "Serve sensitive content over HTTPS (443) instead."}},
        {443, {"HTTPS", "",
               "Encrypted web service. Normal to see.",
               ""}},
        {8080, {"HTTP-alt", "low",
                "Alternate web port, often an admin panel or proxy.",
                "Check what's behind it; admin panels shouldn't face the internet."}},
        {8443, {"HTTPS-alt", "low",
                "Alternate encrypted web port, often an admin panel.",
                "Confirm the panel is meant to be reachable."}},
        {9200, {"Elasticsearch", "high",
                "Search/analytics database, often unauthenticated by default.",
                "Firewall it and enable security. Open Elasticsearch has leaked large datasets."}},
        {161, {"SNMP", "medium",
               "Device management, often left on default community strings.",
               "Change default community strings; restrict access."}},
        {554, {"RTSP", "medium",
               "Streaming, commonly an IP camera. Frequently exposed by accident.",
               "If this is a camera, confirm it should be reachable and has a strong password."}},
        {1883, {"MQTT", "medium",
                "IoT messaging, often without authentication.",
                "Enable auth/TLS; keep IoT brokers off the open internet."}},
        {2323, {"Telnet-alt", "high",
                "Alternate Telnet port, heavily associated with compromised IoT devices.",
                "Disable it. This port answering often means an IoT device is already at risk."}},
    };

    auto it = table.find(port);
    if (it != table.end()) {
        return it->second;
    }
    return ServiceInfo{"unknown", "", "", ""};
}

}  // namespace kahirnet
