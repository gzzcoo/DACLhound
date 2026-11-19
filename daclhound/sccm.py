"""Read-only Configuration Manager discovery and host profiling."""
from __future__ import annotations

import ast
import re
import os
import socket
import ssl
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from typing import Any

from .common import attr, scalar, trustees


def _values(value: Any) -> list[str]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return [_text(item).strip() for item in values if _text(item).strip()]


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", errors="replace")
    text = scalar(value)
    if text.startswith(("b'", 'b"')):
        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, bytes):
                return parsed.rstrip(b"\x00").decode("utf-8", errors="replace")
        except (SyntaxError, ValueError):
            pass
    return text


def _search_filter(clauses: list[str]) -> str:
    return "(|" + "".join(clauses) + ")"


async def discover_sccm(ldap: Any) -> dict[str, Any]:
    """Collect SCCM-related LDAP records using DACLhound's authenticated LDAP session."""
    from bloodyAD.network.ldap import Scope

    from .collector import json_value

    report: dict[str, Any] = {
        "systemManagement": {"found": False, "dn": "", "fullControlPrincipals": [], "aces": []},
        "sites": [],
        "managementPoints": [],
        "potentialDistributionPoints": [],
        "siteDatabases": [],
        "smsProviders": [],
        "principals": [],
        "computers": [],
        "warnings": [],
    }

    async def query(base: str, ldap_filter: str, attributes: list[str], scope: Any = Scope.SUBTREE) -> list[dict[str, Any]]:
        try:
            return [json_value(entry) async for entry in ldap.bloodysearch(
                base, ldap_filter=ldap_filter, search_scope=scope, attr=attributes,
            )]
        except Exception as exc:
            # Missing optional SCCM schema/classes are normal in non-SCCM domains.
            text = str(exc)
            if any(token in text.casefold() for token in ("no result", "no such object", "no such attribute", "objectclass")):
                return []
            report["warnings"].append(f"LDAP query {ldap_filter}: {type(exc).__name__}: {exc}")
            return []

    system_dn = f"CN=System Management,CN=System,{ldap.domainNC}"
    system_entries = await query(system_dn, "(objectClass=*)",
                                 ["distinguishedName", "objectSid", "nTSecurityDescriptor"], Scope.BASE)
    if system_entries:
        system = system_entries[0]
        descriptor = attr(system, "nTSecurityDescriptor", {}) or {}
        if isinstance(descriptor, list):
            descriptor = descriptor[0] if descriptor else {}
        acl = descriptor.get("ACL", []) if isinstance(descriptor, dict) else []
        aces = []
        full_control = set()
        for ace in acl if isinstance(acl, list) else []:
            if not isinstance(ace, dict):
                continue
            right = scalar(ace.get("Right") or ace.get("Mask")).strip()
            trustee = trustees(ace.get("Trustee"))
            ace_type = scalar(ace.get("Type"))
            record = {"trustee": trustee, "right": right,
                      "type": ace_type, "flags": scalar(ace.get("Flags")),
                      "objectType": scalar(ace.get("ObjectType"))}
            aces.append(record)
            normalized_right = right.casefold().replace("_", "").replace(" ", "")
            mask_value = None
            try:
                mask_text = scalar(ace.get("Mask")).strip()
                mask_value = int(mask_text, 0) if mask_text else None
            except ValueError:
                pass
            has_full_control = ("genericall" in normalized_right or "fullcontrol" in normalized_right
                                or (mask_value is not None and mask_value & 0xF01FF == 0xF01FF))
            if ("denied" not in ace_type.casefold()
                    and has_full_control):
                full_control.update(trustee)
        report["systemManagement"] = {
            "found": True,
            "dn": scalar(attr(system, "distinguishedName")),
            "fullControlPrincipals": sorted(full_control, key=str.casefold),
            "aces": aces,
        }

    site_entries = await query(ldap.domainNC, "(objectClass=mSSMSSite)",
                               ["distinguishedName", "mSSMSSiteCode", "name"])
    for entry in site_entries:
        report["sites"].append({
            "dn": scalar(attr(entry, "distinguishedName")),
            "siteCode": _text(attr(entry, "mSSMSSiteCode")),
            "name": scalar(attr(entry, "name")),
        })

    mp_entries = await query(ldap.domainNC, "(objectClass=mSSMSManagementPoint)",
                             ["distinguishedName", "dNSHostName", "mSSMSSiteCode"])
    for entry in mp_entries:
        report["managementPoints"].append({
            "dn": scalar(attr(entry, "distinguishedName")),
            "hostname": scalar(attr(entry, "dNSHostName")).rstrip("."),
            "siteCode": _text(attr(entry, "mSSMSSiteCode")),
        })

    pxe_entries = await query(ldap.domainNC, "(&(objectClass=connectionPoint)(netbootServer=*))",
                              ["distinguishedName", "netbootServer"])
    for entry in pxe_entries:
        dn = scalar(attr(entry, "distinguishedName"))
        computer_dn = dn.split(",", 1)[1] if "," in dn else ""
        hosts = await query(computer_dn, "(objectClass=computer)",
                            ["distinguishedName", "dNSHostName"], Scope.BASE) if computer_dn else []
        report["potentialDistributionPoints"].append({
            "dn": dn,
            "hostname": scalar(attr(hosts[0], "dNSHostName")).rstrip(".") if hosts else "",
            "evidence": "LDAP connectionPoint with netbootServer",
        })

    principal_filter = _search_filter([
        f"({attribute}=*{term}*)"
        for attribute in ("sAMAccountName", "description", "name")
        for term in ("SCCM", "MECM")
    ])
    principal_entries = await query(ldap.domainNC, principal_filter,
                                    ["distinguishedName", "objectClass", "objectSid", "cn", "name",
                                     "sAMAccountName", "description", "member", "servicePrincipalName"])
    for entry in principal_entries:
        report["principals"].append({
            "dn": scalar(attr(entry, "distinguishedName")),
            "objectClass": _values(attr(entry, "objectClass")),
            "sid": scalar(attr(entry, "objectSid")),
            "name": scalar(attr(entry, "name") or attr(entry, "cn")),
            "sAMAccountName": scalar(attr(entry, "sAMAccountName")),
            "description": scalar(attr(entry, "description")),
            "members": _values(attr(entry, "member")),
            "servicePrincipalNames": _values(attr(entry, "servicePrincipalName")),
        })

    computer_entries = await query(ldap.domainNC, "(objectCategory=computer)",
                                   ["distinguishedName", "objectSid", "sAMAccountName", "dNSHostName",
                                    "operatingSystem", "operatingSystemVersion"])
    for entry in computer_entries:
        hostname = scalar(attr(entry, "dNSHostName")).strip().rstrip(".")
        if hostname:
            report["computers"].append({
                "dn": scalar(attr(entry, "distinguishedName")),
                "sid": scalar(attr(entry, "objectSid")),
                "hostname": hostname,
                "sAMAccountName": scalar(attr(entry, "sAMAccountName")),
                "operatingSystem": scalar(attr(entry, "operatingSystem")),
                "operatingSystemVersion": scalar(attr(entry, "operatingSystemVersion")),
                "resolvedAddresses": [],
                "dnsStatus": "not-queried",
                "tcpIndicators": {},
                "smb": {"status": "not-queried", "signingRequired": None, "shares": [], "roles": []},
            })
    management_hosts = {item["hostname"].casefold() for item in report["managementPoints"] if item["hostname"]}
    site_codes_by_host: dict[str, set[str]] = {}
    for item in report["managementPoints"]:
        if item["hostname"] and item["siteCode"]:
            site_codes_by_host.setdefault(item["hostname"].casefold(), set()).add(item["siteCode"])
    pxe_hosts = {item["hostname"].casefold() for item in report["potentialDistributionPoints"] if item["hostname"]}
    full_control_principals = {item.casefold() for item in report["systemManagement"]["fullControlPrincipals"]}
    full_control_computers = []
    matched_full_control_sids = set()
    for computer in report["computers"]:
        roles = []
        host = computer["hostname"].casefold()
        if host in management_hosts:
            roles.append("management-point")
        if host in pxe_hosts:
            roles.append("potential-distribution-point")
        if computer["sid"].casefold() in full_control_principals:
            roles.append("System Management full control")
            full_control_computers.append(computer["hostname"])
            matched_full_control_sids.add(computer["sid"].casefold())
        computer["ldapRoles"] = roles
        computer["ldapSiteCodes"] = sorted(site_codes_by_host.get(host, set()))
    report["systemManagement"]["fullControlComputerNames"] = sorted(full_control_computers, key=str.casefold)
    return report


def resolve_sccm_hosts(report: dict[str, Any], dns_server: str, timeout: int = 3) -> None:
    """Resolve names against the selected DNS server without consulting or editing hosts files."""
    try:
        import dns.resolver
    except ImportError as exc:
        raise RuntimeError("SCCM DNS resolution requires dnspython") from exc
    def resolve(computer: dict[str, Any]) -> None:
        hostname = computer["hostname"]
        addresses: set[str] = set()
        failures = []
        for record_type in ("A", "AAAA"):
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [dns_server]
                resolver.timeout = timeout
                resolver.lifetime = timeout
                addresses.update(str(answer) for answer in resolver.resolve(hostname, record_type))
            except Exception as exc:
                failures.append(type(exc).__name__)
        computer["resolvedAddresses"] = sorted(addresses)
        computer["dnsStatus"] = "resolved" if addresses else "unresolved"
        if not addresses:
            computer["dnsError"] = ", ".join(sorted(set(failures)))

    computers = report.get("computers", [])
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(resolve, computer) for computer in computers]
        for future in as_completed(futures):
            future.result()


def profile_sccm_smb(
    report: dict[str, Any], *, username: str, domain: str, password: str = "",
    hashes: str = "", aes_key: str = "", kerberos: bool = False,
    ccache: str | None = None, kdc_host: str = "", timeout: int = 3,
) -> None:
    """Read SMB negotiation and share metadata from discovered AD computers."""
    from impacket.smbconnection import SMBConnection

    lmhash, nthash = (hashes.split(":", 1) if ":" in hashes else ("", hashes))
    computers = report.get("computers", [])

    def profile(computer: dict[str, Any]) -> None:
        addresses = computer.get("resolvedAddresses") or []
        if not addresses:
            return
        hostname = computer["hostname"]
        last_error = ""
        address = addresses[0]
        computer["tcpIndicators"] = {
            "mssql1433": _tcp_reachable(address, 1433, timeout),
            "wsus8530": _tcp_reachable(address, 8530, timeout),
            "wsus8531": _tcp_reachable(address, 8531, timeout),
        }
        for address in addresses:
            connection = None
            try:
                connection = SMBConnection(remoteName=hostname, remoteHost=address, timeout=timeout)
                signing_required, signing_dialect = _probe_smb_signing(hostname, address, timeout)
                connection.kerberosLogin(username, password, domain, lmhash, nthash,
                                         aes_key, kdc_host or None) if kerberos else connection.login(
                                             username, password, domain, lmhash, nthash)
                shares = []
                roles: set[str] = set()
                site_codes: set[str] = set()
                for share in connection.listShares():
                    # Impacket returns SHARE_INFO_1 NDR structures here, not
                    # dictionaries. NDR fields support key access but no get().
                    name = _decode_share(_share_field(share, "shi1_netname")).upper()
                    normalized_name = name.rstrip("$")
                    remark = _decode_share(_share_field(share, "shi1_remark"))
                    shares.append({"name": name, "remark": remark})
                    if normalized_name == "SMS_DP":
                        roles.add("distribution-point")
                    if normalized_name.startswith("SMSPKG"):
                        roles.add("distribution-point")
                    if normalized_name == "REMINST" and "WINDOWS DEPLOYMENT SERVICES" in remark.upper():
                        roles.add("wds-pxe")
                    if "CONFIGMGR SITE SERVER" in remark.upper():
                        roles.add("site-server")
                    match = re.search(r"SMS Site\s+([A-Za-z0-9_-]+)", remark, re.IGNORECASE)
                    if match:
                        site_codes.add(match.group(1).upper())
                computer["smb"] = {
                    "status": "authenticated",
                    "address": address,
                    "signingRequired": signing_required,
                    "signingProbeDialect": signing_dialect,
                    "shares": shares,
                    "roles": sorted(roles),
                    "siteCodes": sorted(site_codes),
                }
                ldap_roles = {str(role).strip().casefold().replace("_", "-")
                              for role in computer.get("ldapRoles", [])}
                if "site-server" in roles or "system management full control" in ldap_roles:
                    databases, registry_status = _read_site_database_candidates(connection)
                    computer["siteDatabaseRegistryStatus"] = registry_status
                    computer["siteDatabaseCandidates"] = databases
                break
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                # Preserve the server policy even when authentication fails;
                # do not use isSigningRequired() on an SMB 3.1.1 connection.
                if connection is not None:
                    try:
                        signing_required, signing_dialect = _probe_smb_signing(hostname, address, timeout)
                        computer["smb"] = {
                            "status": "authentication-failed", "address": address,
                            "signingRequired": signing_required,
                            "signingProbeDialect": signing_dialect,
                            "shares": [], "roles": [], "error": last_error,
                        }
                    except Exception:
                        pass
            finally:
                if connection is not None:
                    try:
                        connection.logoff()
                    except Exception:
                        pass
        if last_error and computer["smb"].get("status") == "not-queried":
            computer["smb"] = {"status": "unavailable", "signingRequired": None,
                               "shares": [], "roles": [], "error": last_error}

    old_ccache = os.environ.get("KRB5CCNAME")
    if kerberos and ccache:
        os.environ["KRB5CCNAME"] = ccache
    try:
        total = len(computers)
        message = f"Profiling SMB on {total} SCCM candidate computers"
        tty = sys.stderr.isatty()
        if tty:
            print(_colored_status("*", message, "1;34"), end="", file=sys.stderr, flush=True)
        else:
            print(_colored_status("*", message, "1;34"), file=sys.stderr)
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(profile, computer): computer for computer in computers}
            pending = set(futures)
            completed = 0
            spinner = "|/-\\"
            tick = 0
            latest = ""
            try:
                while pending:
                    done, pending = wait(pending, timeout=0.4, return_when=FIRST_COMPLETED)
                    for future in done:
                        computer = futures[future]
                        future.result()
                        completed += 1
                        smb_status = computer.get("smb", {}).get("status", "not-queried")
                        if not computer.get("resolvedAddresses"):
                            smb_status = "DNS unresolved, skipped"
                        latest = f"{computer.get('hostname', 'unknown host')}: {smb_status}"
                        if not tty:
                            print(_colored_status("*", f"SCCM SMB {completed}/{total} · {latest}", "1;34"),
                                  file=sys.stderr)
                    if tty:
                        progress = f"{message} · {completed}/{total} completed"
                        if latest:
                            progress += f" · Latest: {latest}"
                        frame = spinner[tick % len(spinner)]
                        tick += 1
                        print("\r" + _colored_status("*", f"{progress} {frame}", "1;34") + "\x1b[K",
                              end="", file=sys.stderr, flush=True)
            finally:
                if tty:
                    print(file=sys.stderr, flush=True)
    finally:
        if kerberos and ccache:
            if old_ccache is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = old_ccache

    # Full Control on System Management is strong evidence for a site-server
    # candidate. Some collectors cannot resolve that ACE, so also use the
    # ConfigMgr site shares to identify a passive peer when an active server
    # for the same site is independently visible.
    for computer in computers:
        ldap_roles = {str(role).strip().casefold().replace("_", "-")
                      for role in computer.get("ldapRoles", [])}
        smb = computer.get("smb", {})
        if smb.get("status") != "authenticated":
            continue
        smb_roles = {str(role).strip().casefold().replace("_", "-")
                     for role in smb.get("roles", [])}
        if "system management full control" in ldap_roles:
            computer["siteServerConfiguration"] = "Active" if "site-server" in smb_roles else "Passive"
            computer["siteServerDetection"] = "System Management Full Control + SMB shares"

    active_sites: dict[str, set[str]] = {}
    for computer in computers:
        smb = computer.get("smb", {})
        if smb.get("status") != "authenticated" or "site-server" not in smb.get("roles", []):
            continue
        for code in smb.get("siteCodes", []):
            active_sites.setdefault(str(code).strip().casefold(), set()).add(
                str(computer.get("hostname", "")).strip().casefold()
            )
    for computer in computers:
        smb = computer.get("smb", {})
        if smb.get("status") != "authenticated" or computer.get("siteServerConfiguration"):
            continue
        share_names = {str(share.get("name", "")).strip().rstrip("$").upper()
                       for share in smb.get("shares", [])}
        site_codes = {str(code).strip().casefold() for code in smb.get("siteCodes", [])}
        has_site_server_shares = "SMS_SITE" in share_names or any(
            f"SMS_{code.upper()}" in share_names for code in site_codes
        )
        hostname = str(computer.get("hostname", "")).strip().casefold()
        if has_site_server_shares and any(
            active_sites.get(code, set()) - {hostname} for code in site_codes
        ):
            computer["siteServerConfiguration"] = "Passive"
            computer["siteServerDetection"] = "site-share evidence + active peer for the same site"

    def is_admin_service_candidate(computer: dict[str, Any]) -> bool:
        """Limit HTTP role checks to hosts already identified as SCCM assets."""
        hostname = str(computer.get("hostname") or "").casefold()
        roles = {
            str(role).strip().casefold().replace("_", "-")
            for role in [*(computer.get("ldapRoles") or []), *((computer.get("smb") or {}).get("roles") or [])]
        }
        known_sccm_role = bool(roles & {
            "management-point", "potential-distribution-point", "distribution-point",
            "site-server", "system management full control", "sms-provider",
        }) or bool(computer.get("siteServerConfiguration"))
        sccm_named_host = bool(re.search(r"(?:sccm|mecm)", hostname))
        database_candidate = bool(computer.get("siteDatabaseCandidates"))
        return known_sccm_role or sccm_named_host or database_candidate

    def profile_admin_service(computer: dict[str, Any]) -> None:
        computer["adminService"] = _probe_admin_service(
            computer["hostname"], computer.get("resolvedAddresses") or [], timeout,
        )

    admin_service_candidates = [computer for computer in computers if is_admin_service_candidate(computer)]
    for computer in computers:
        if computer not in admin_service_candidates:
            computer["adminService"] = {"providerDetected": False, "ntlmSupported": False,
                                        "ntlmAdvertised": False, "ntlmRelayCandidate": False,
                                        "probeStatus": "not-an-sccm-host-candidate",
                                        "endpoint": "", "statusCode": None, "authSchemes": []}
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(profile_admin_service, computer) for computer in admin_service_candidates]
        for future in as_completed(futures):
            future.result()

    site_databases: dict[tuple[str, str], dict[str, Any]] = {}
    for computer in computers:
        site_codes = sorted(set(computer.get("ldapSiteCodes", []))
                            | set((computer.get("smb") or {}).get("siteCodes", [])))
        for hostname in computer.get("siteDatabaseCandidates", []):
            key = (computer["hostname"].casefold(), hostname.casefold())
            site_databases[key] = {
                "siteServer": computer["hostname"],
                "siteCodes": site_codes,
                "hostname": hostname,
                "discovery": "Remote Registry · Multisite Component Servers",
                "registryStatus": computer.get("siteDatabaseRegistryStatus", "unavailable"),
            }
    # If Remote Registry could not be queried, retain a clearly unverified
    # candidate when a separate SCCM-associated host exposes MSSQL/1433.
    known_database_hosts = {
        (item["siteServer"].casefold(), item["hostname"].casefold())
        for item in site_databases.values()
    }
    site_codes_available = {str(site.get("siteCode", "")).casefold()
                            for site in report.get("sites", []) if site.get("siteCode")}
    for primary in computers:
        registry_status = str(primary.get("siteDatabaseRegistryStatus") or "")
        smb = primary.get("smb") or {}
        roles = {str(role).strip().casefold().replace("_", "-")
                 for role in [*(primary.get("ldapRoles") or []), *(smb.get("roles") or [])]}
        is_site_server = "site-server" in roles or bool(primary.get("siteServerConfiguration"))
        if not is_site_server or not registry_status.startswith("unavailable:"):
            continue
        primary_codes = {str(code).casefold() for code in
                         [*(primary.get("ldapSiteCodes") or []), *(smb.get("siteCodes") or [])] if code}
        for candidate in computers:
            hostname = str(candidate.get("hostname") or "").strip().rstrip(".")
            if not hostname or hostname.casefold() == str(primary.get("hostname", "")).casefold():
                continue
            tcp = candidate.get("tcpIndicators") or {}
            if tcp.get("mssql1433") is not True:
                continue
            candidate_smb = candidate.get("smb") or {}
            candidate_codes = {str(code).casefold() for code in
                               [*(candidate.get("ldapSiteCodes") or []), *(candidate_smb.get("siteCodes") or [])] if code}
            shared_codes = primary_codes & candidate_codes
            if not shared_codes and not (len(site_codes_available) == 1 and
                                         (not primary_codes or not candidate_codes)):
                continue
            key = (str(primary.get("hostname", "")).casefold(), hostname.casefold())
            if key in known_database_hosts:
                continue
            site_databases[key] = {
                "siteServer": primary.get("hostname", ""),
                "siteCodes": sorted(shared_codes) or sorted(primary_codes) or sorted(site_codes_available),
                "hostname": hostname,
                "discovery": "TCP/1433 fallback · SCCM site association; database role unconfirmed",
                "registryStatus": registry_status,
            }
    report["siteDatabases"] = sorted(site_databases.values(),
                                     key=lambda item: (item["siteServer"].casefold(), item["hostname"].casefold()))
    report["smsProviders"] = [
        {"hostname": computer["hostname"], **computer["adminService"]}
        for computer in computers if computer.get("adminService", {}).get("providerDetected")
    ]


_SITE_DATABASE_REGISTRY_KEY = (
    r"SOFTWARE\Microsoft\SMS\components\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers"
)


def _read_site_database_candidates(connection: Any) -> tuple[list[str], str]:
    """Read SCCM's potential remote database servers without starting RemoteRegistry."""
    from impacket.dcerpc.v5 import rrp, transport

    dce = None
    try:
        rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
        rpc.set_smb_connection(connection)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        root = rrp.hOpenLocalMachine(dce)["phKey"]
        key = rrp.hBaseRegOpenKey(
            dce, root, _SITE_DATABASE_REGISTRY_KEY,
            samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE,
        )["phkResult"]
        candidates = []
        index = 0
        while True:
            try:
                name = _text(rrp.hBaseRegEnumKey(dce, key, index)["lpNameOut"])
            except rrp.DCERPCSessionError as exc:
                if exc.get_error_code() == 259:  # ERROR_NO_MORE_ITEMS
                    break
                return candidates, f"read-error: {type(exc).__name__}"
            if name and name not in candidates:
                candidates.append(name.rstrip("\x00.\\"))
            index += 1
        return candidates, "queried"
    except Exception as exc:
        # RemoteRegistry may be disabled; do not start/change it during collection.
        return [], f"unavailable: {type(exc).__name__}"
    finally:
        if dce is not None:
            try:
                dce.disconnect()
            except Exception:
                pass


def _probe_admin_service(hostname: str, addresses: list[str], timeout: int) -> dict[str, Any]:
    """Identify an SMS Provider using the same AdminService challenge as SCCMHunter."""
    endpoint_path = "/AdminService/wmi/"
    result: dict[str, Any] = {"providerDetected": False, "ntlmSupported": False,
                              "ntlmAdvertised": False, "ntlmRelayCandidate": False,
                              "endpoint": "", "statusCode": None, "authSchemes": []}
    for scheme, port in (("https", 443), ("http", 80)):
        for address in addresses:
            raw = None
            try:
                raw = socket.create_connection((address, port), timeout=timeout)
                raw.settimeout(timeout)
                sock = raw
                if scheme == "https":
                    context = ssl._create_unverified_context()
                    sock = context.wrap_socket(raw, server_hostname=hostname)
                sock.sendall((f"GET {endpoint_path} HTTP/1.1\r\nHost: {hostname}\r\n"
                              "Connection: close\r\nUser-Agent: DACLhound SCCM inventory\r\n\r\n").encode("ascii"))
                response = b""
                while b"\r\n\r\n" not in response and len(response) < 16384:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    response += chunk
                header = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
                lines = header.split("\r\n")
                match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0]) if lines else None
                if not match:
                    continue
                status = int(match.group(1))
                challenges = [line.split(":", 1)[1].strip() for line in lines[1:]
                              if line.casefold().startswith("www-authenticate:")]
                schemes = sorted({token for challenge in challenges
                                  for token in re.findall(r"(?i)(?<![A-Za-z])(?:NTLM|Negotiate|Basic|Digest)(?![A-Za-z])", challenge)})
                detected = status in (200, 401, 403)
                supports_ntlm = any(re.search(r"(?i)(?:^|[,\s])NTLM(?:$|[,\s])", challenge)
                                    for challenge in challenges)
                # AdminService advertises Negotiate; on pre-2509 ConfigMgr this
                # can negotiate NTLM and is relayable even without a bare NTLM token.
                relay_candidate = supports_ntlm or "NEGOTIATE" in {item.upper() for item in schemes}
                result = {"providerDetected": detected, "ntlmSupported": relay_candidate,
                          "ntlmAdvertised": supports_ntlm, "ntlmRelayCandidate": relay_candidate,
                          "probeStatus": "provider-detected" if detected else "not-provider",
                          "endpoint": f"{scheme}://{hostname}:{port}{endpoint_path}",
                          "statusCode": status, "authSchemes": schemes}
                if detected and relay_candidate:
                    return result
                if detected:
                    break
            except (OSError, ssl.SSLError, UnicodeError):
                continue
            finally:
                try:
                    if raw is not None:
                        raw.close()
                except OSError:
                    pass
    return result


def _decode_share(value: Any) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", errors="replace")
    return scalar(value).rstrip("\x00")


def _share_field(share: Any, name: str) -> Any:
    if isinstance(share, dict):
        return share.get(name, "")
    try:
        return share[name]
    except (KeyError, TypeError, AttributeError):
        return getattr(share, name, "")


def _tcp_reachable(host: str, port: int, timeout: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_smb_signing(hostname: str, address: str, timeout: int) -> tuple[bool | None, str | None]:
    """Read server-side SMB signing policy without Impacket's SMB 3.1.1 shortcut.

    Impacket currently reports SMB 3.1.1 as requiring signing even when the
    server's NEGOTIATE SecurityMode does not set SIGNING_REQUIRED. Pin the
    read-only probe to SMB 3.0/2.1, where that server flag is respected.
    """
    from impacket.smb3structs import SMB2_DIALECT_21, SMB2_DIALECT_30
    from impacket.smbconnection import SMBConnection

    for dialect, label in ((SMB2_DIALECT_30, "SMB 3.0"), (SMB2_DIALECT_21, "SMB 2.1")):
        connection = None
        try:
            connection = SMBConnection(remoteName=hostname, remoteHost=address,
                                       timeout=timeout, preferredDialect=dialect)
            return bool(connection.isSigningRequired()), label
        except Exception:
            continue
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
    return None, None


def _colored_status(marker: str, message: str, color: str) -> str:
    if not sys.stderr.isatty():
        return f"[{marker}] {message}"
    return f"\x1b[{color}m[{marker}]\x1b[0m {message}"


def print_sccm_summary(report: dict[str, Any]) -> None:
    """Print a compact SCCM summary; detailed evidence remains in the graph JSON."""
    computers = report.get("computers", [])
    sites = report.get("sites", [])
    management_points = report.get("managementPoints", [])
    pxe_points = report.get("potentialDistributionPoints", [])
    site_names = [site.get("siteCode") for site in sites if site.get("siteCode")]
    mp_hosts = [point.get("hostname") for point in management_points if point.get("hostname")]
    pxe_hosts = [point.get("hostname") for point in pxe_points if point.get("hostname")]
    site_text = f"{len(sites)}" + (f" ({', '.join(site_names)})" if site_names else "")
    mp_text = f"{len(management_points)}" + (f" ({', '.join(mp_hosts)})" if mp_hosts else "")
    pxe_text = f"{len(pxe_points)}" + (f" ({', '.join(pxe_hosts)})" if pxe_hosts else "")
    print(_colored_status("+", f"SCCM: {site_text} sites | {mp_text} Management Points | "
                          f"{pxe_text} potential PXE DPs | {len(report.get('principals', []))} principals",
                          "1;32"), file=sys.stdout)

    resolved = sum(computer.get("dnsStatus") == "resolved" for computer in computers)
    smb_attempted = sum(bool(computer.get("resolvedAddresses")) for computer in computers)
    smb_authenticated = sum(computer.get("smb", {}).get("status") == "authenticated" for computer in computers)
    signing_required = sum(computer.get("smb", {}).get("signingRequired") is True for computer in computers)
    print(_colored_status("+", f"SCCM hosts: {len(computers)} | DNS {resolved}/{len(computers)} | "
                          f"SMB authenticated {smb_authenticated}/{smb_attempted} | "
                          f"SMB signing required {signing_required}/{smb_attempted}", "1;32"),
          file=sys.stdout)

    system = report.get("systemManagement", {})
    full_control_hosts = system.get("fullControlComputerNames", [])
    full_control = full_control_hosts or system.get("fullControlPrincipals", [])
    if system.get("found"):
        print(_colored_status("+", f"System Management Full Control: "
                              f"{', '.join(full_control) if full_control else 'no computer trustees resolved'}",
                              "1;32"), file=sys.stdout)

    indicators: dict[str, list[str]] = {"MSSQL/1433": [], "WSUS/8530": [], "WSUS/8531": []}
    for computer in computers:
        ports = computer.get("tcpIndicators", {})
        for key, label in (("mssql1433", "MSSQL/1433"), ("wsus8530", "WSUS/8530"), ("wsus8531", "WSUS/8531")):
            if ports.get(key):
                indicators[label].append(computer.get("hostname", "unknown"))
    open_indicators = [f"{label}: {', '.join(hosts)}" for label, hosts in indicators.items() if hosts]
    if open_indicators:
        print(_colored_status("+", f"TCP indicators: {' | '.join(open_indicators)}", "1;32"),
              file=sys.stdout)
