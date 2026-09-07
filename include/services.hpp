#pragma once

#include <cstdint>
#include <string>

namespace kahirnet {

struct ServiceInfo {
    std::string name;      // human name of the service usually on this port
    std::string exposure;  // "", "low", "medium", "high" -- risk of finding it reachable
    std::string note;      // plain-language explanation of why it matters
    std::string advice;    // what a non-expert should consider doing
};

// Returns what is commonly found on a TCP port, plus a plain-language
// exposure assessment. The exposure rating is about the risk of that
// service being reachable at all from where the scan runs -- a database
// or a remote-desktop port answering is a posture problem regardless of
// whether it is currently vulnerable. Empty exposure means "normal to
// see, no inherent concern".
ServiceInfo service_for_port(uint16_t port);

}  // namespace kahirnet
