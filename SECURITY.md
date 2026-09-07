# Security Policy

KAHIRNET is an authorized-use, connect-only network reconnaissance tool.

It must not be extended to:

- send exploits or attempt to compromise any host,
- perform raw/SYN/spoofed packet scanning,
- brute-force credentials or authenticate to services,
- modify anything on a scanned host,
- run without the --yes-authorized confirmation.

Banners and service data come from third-party hosts and are treated as
untrusted input: escaped before entering JSON/HTML reports, and never
executed or interpreted.

Only scan networks you own or have written permission to test.
