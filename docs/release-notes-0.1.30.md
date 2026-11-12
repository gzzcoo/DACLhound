# DACLhound 0.1.30

## Added

- Optional host checks report SMB signing requirements and WebClient availability through the `DAV RPC Service` SMB named pipe. The collector summary now includes MachineAccountQuota when available.
- The graph viewer separates global object search from search within currently visible nodes, adds dataset management beside **Add data**, and provides clearer query/pathfinding state and graph restoration guidance.
- Saved queries now include improved domain, OU, privileged-group, and DCSync views.

## Enhancements

- Collection output now uses consistent colored status markers and summarizes object types, ACEs, trustees, ADCS findings, and MachineAccountQuota.
- Graph query results are centered and fitted more consistently. Labels, node placement, zoom behavior, search suggestions, and Light theme controls have been refined.
- DCSync findings are summarized per principal and target to reduce redundant graph edges.

## Bug Fixes

- Correctly parse numeric user-account-control flags and derive enabled, Kerberos exposure, password, script, operating-system, and gMSA properties.
- Retry Kerberos ticket acquisition after clock-skew errors using an in-memory time offset without changing the system clock.
- Improve ADCS ESC17 classification and reduce false-positive privileged-principal findings.
- Preserve Enterprise Admin membership and improve the handling of query results, empty result sets, and graph positions during interaction.
