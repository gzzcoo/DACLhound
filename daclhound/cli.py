"""Command-line interface for DACLhound."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import analyze_graph_files
from .collector import (
    build_dataset,
    collect_host_service_checks,
    collect_with_bloodyad,
    ensure_bloodyad_available,
    _status,
)
from .common import classify, scalar, stable_id
from .graph_control import (
    _graph_daemon_matches,
    _graph_pid_file,
    _read_graph_pid,
    _start_graph_server,
    _stop_graph_server,
)
from .server import run_server


def _paint(text: str, *codes: str, stream: Any = sys.stdout) -> str:
    """Apply ANSI styling only when output is connected to a terminal."""
    if not getattr(stream, "isatty", lambda: False)():
        return text
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"


def _print_banner() -> None:
    """Print the CLI identity and leave a blank line before command output."""
    print(_paint("DACLhound", "1", "38;2;220;88;82") +
          f" v{__version__} - by Jeremy Rodriguez (gzzcoo)", flush=True)
    print(flush=True)


def _print_collection_summary(dataset: dict[str, Any], output: Path) -> None:
    nodes = dataset.get("nodes", [])
    type_labels = (
        ("user", "users"), ("group", "groups"), ("computer", "computers"),
        ("ou", "OUs"), ("container", "containers"), ("gpo", "GPOs"),
        ("domain", "domains"), ("trusted_domain", "trusts"), ("site", "sites"),
        ("foreign_security_principal", "foreign security principals"),
        ("cert_template", "certificate templates"), ("enterprise_ca", "enterprise CAs"),
        ("root_ca", "root CAs"), ("adcs_policy", "issuance policies"),
    )
    counts = {kind: sum(node.get("type") == kind for node in nodes) for kind, _ in type_labels}
    present = [f"{counts[kind]:,} {label}" for kind, label in type_labels if counts[kind]]
    stats = dataset.get("stats", {})
    print()
    print(_paint("DACLhound", "1", "38;2;220;88;82") + " " + _paint("Enumeration completed!", "1"))
    print()
    print(f"{_paint('[+]', '1', '32')} Objects: {stats.get('objects', 0):,}" +
          (f" ({' | '.join(present)})" if present else ""))
    print(f"{_paint('[+]', '1', '32')} Relationships: {stats.get('aces', 0):,} ACEs | "
          f"{stats.get('trustees', 0):,} trustees | "
          f"{stats.get('adcsFindings', 0):,} ADCS findings")
    quota = stats.get("machineAccountQuota")
    quota_display = quota if quota not in (None, "") else "not collected"
    print(f"{_paint('[+]', '1', '32')} MachineAccountQuota: {quota_display}")
    print(f"{_paint('[+]', '1', '32')} Graph: {output}")


def _output_candidate(path: Path, index: int) -> Path:
    if index == 0:
        return path
    return path.with_name(f"{path.stem}_{index}{path.suffix}")


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _default_output_path(domain: str) -> Path:
    label = re.sub(r"[^a-zA-Z0-9.-]+", "_", domain.strip().rstrip(".").lower()).strip("._-")
    return Path(f"{label or 'daclgraph'}.json")


def _domain_from_dn(dn: str) -> str:
    labels = [part.split("=", 1)[1].strip() for part in dn.split(",")
              if "=" in part and part.split("=", 1)[0].strip().casefold() == "dc"]
    return ".".join(labels)


def _target_domain(entries: list[dict[str, Any]], fallback: str) -> str:
    """Prefer the queried domain naming context over the authentication realm."""
    candidates: dict[str, int] = {}
    for entry in entries:
        name = _domain_from_dn(scalar(entry.get("distinguishedName")))
        if name:
            candidates[name] = candidates.get(name, 0) + 1
    return max(candidates, key=candidates.get) if candidates else fallback


def _resolve_output_paths(
    domain: str,
    output: str | None,
    raw_output: str | None,
    overwrite: bool,
) -> tuple[Path, Path | None]:
    base_output = Path(output) if output else _default_output_path(domain)
    base_raw = Path(raw_output) if raw_output else None
    for index in range(1_000_000):
        graph_path = _output_candidate(base_output, index)
        if raw_output is None:
            raw_path = None
        elif raw_output == "":
            raw_path = graph_path.with_name(f"{graph_path.stem}.raw.json")
        else:
            assert base_raw is not None
            raw_path = _output_candidate(base_raw, index)
        if raw_path is not None and graph_path.resolve() == raw_path.resolve():
            raise RuntimeError("Graph output and raw output must use different paths")
        if overwrite or not any(_path_exists(path) for path in (graph_path, raw_path) if path is not None):
            return graph_path, raw_path
    raise RuntimeError("Could not find an unused output filename")


def main() -> int:
    if "--_daemon-child" not in sys.argv:
        _print_banner()
    parser = argparse.ArgumentParser(
        prog="daclhound",
        description="Collect, analyze, or graph Active Directory DACL data.",
    )
    parser.add_argument("--version", action="version", version=f"DACLhound {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    ap = commands.add_parser(
        "collect", description="Read-only Active Directory DACL collector using LDAP or native ADWS.",
        help="Collect DACLs and write a normalized graph JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  daclhound collect --host DC01.lab.local -d lab.local -u 'user' -p 'password' --dc-ip 192.168.2.1",
    )
    auth = ap.add_argument_group("authentication")
    auth.add_argument("-H", "--host", required=True, help="Domain controller hostname or IP")
    auth.add_argument("-d", dest="domain", required=True, metavar="DOMAIN", help="Domain used for authentication")
    auth.add_argument("-u", dest="username", metavar="USERNAME",
                      help="Username used for NTLM or Kerberos authentication")
    auth.add_argument("-p", dest="password", metavar="PASSWORD",
                      help="Password for NTLM, or for Kerberos when combined with -k")
    auth.add_argument("-hashes", dest="nt_hash", metavar="LMHASH:NTHASH",
                      help="NT hash or LMHASH:NTHASH for PtH; with -k, use the NT hash as the Kerberos RC4 key")
    auth.add_argument("-aesKey", dest="aes_key", metavar="AESKEY",
                      help="Kerberos AES key; enables Kerberos authentication automatically")
    auth.add_argument("-k", "--kerberos", nargs="?", const="", metavar="CCACHE",
                      help="Use Kerberos; read KRB5CCNAME, provide a ccache path, or combine with -p/-hashes")
    auth.add_argument("-no-pass", dest="no_pass", action="store_true",
                      help="Do not use a password; authenticate with the ccache selected by -k or KRB5CCNAME")

    collection = ap.add_argument_group("collection")
    collection.add_argument("--transport", choices=("auto", "ldap", "adws"), default="auto",
                            help="Collection transport: try LDAP then ADWS on connection failure (default), or force one")
    collection.add_argument("--types", default="users,groups,computers,ous,containers,gpos,domain,trusts,sites,foreign-security-principals",
                            help="Comma-separated object types: users, groups, computers, OUs, containers, GPOs, domain, trusts, sites, foreign-security-principals")
    collection.add_argument("--no-adcs", action="store_true", help="Skip native ADCS ESC collection (enabled by default)")
    collection.add_argument("--host-checks", action="store_true",
                            help="Check SMB signing and WebClient status on collected computers")
    collection.add_argument("--host-check-timeout", type=int, default=5, metavar="SECONDS",
                            help="Per-computer SMB probe timeout when --host-checks is enabled (default: 5)")

    output = ap.add_argument_group("output")
    output.add_argument("-o", "--output", help="Custom path for normalized graph JSON (default: DOMAIN.json)")
    output.add_argument("--overwrite", action="store_true",
                        help="Overwrite the selected graph and raw output files instead of adding a numeric suffix")
    output.add_argument("--raw-output", nargs="?", const="", metavar="FILE",
                        help="Also save raw collector data (optional; defaults to the selected graph name plus .raw.json)")
    output.add_argument("--from-raw", help="Build the graph from an existing raw JSON file without querying LDAP")

    connection = ap.add_argument_group("connection")
    connection.add_argument("-i", "--dc-ip", help="Domain controller IP when -H is a hostname")
    connection.add_argument("--dns-server", help="DNS server for --host-checks (defaults to --dc-ip)")
    connection.add_argument("-s", "--secure", action="store_true", help="Use LDAPS (LDAP transport only)")
    connection.add_argument("-t", "--timeout", type=int, default=180, help="Connection timeout in seconds")
    graph = commands.add_parser(
        "graph", help="Serve a graph JSON in the interactive web viewer",
        description="Run the graph viewer in this terminal or manage it as a background service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  daclhound graph start --input <domain>.json\n"
                "  daclhound graph stop\n"
                "  daclhound graph --input <domain>.json  # foreground; stop with Ctrl+C\n"
                "  daclhound graph --verbose             # print HTTP request logs"),
    )
    graph.add_argument("action", nargs="?", choices=("run", "start", "stop", "status"), default="run",
                       help="run in this terminal, start in the background, or stop/status a background server")
    graph.add_argument("--input", help="Optional normalized daclgraph JSON to preload")
    graph.add_argument("--bind", default="127.0.0.1", help="Web server bind address (default: 127.0.0.1)")
    graph.add_argument("--port", type=int, default=8765, help="Web server port (default: 8765)")
    graph.add_argument("--verbose", action="store_true", help="Log each HTTP request")
    graph.add_argument("--_daemon-child", action="store_true", help=argparse.SUPPRESS)
    graph.add_argument("--_pid-file", help=argparse.SUPPRESS)
    analyze = commands.add_parser(
        "analyze", help="Find notable permissions and paths in graph JSON files",
        description="Offline permission and path analysis for normalized DACLhound graph JSON files.",
    )
    analyze.add_argument("json_files", nargs="+", metavar="JSON", help="One or more normalized graph JSON files")
    analyze.add_argument("--from-user", metavar="USER", help="Trace effective permissions and chains from this user")
    analyze.add_argument("--limit", type=int, default=0,
                         help="Maximum relationships/paths to print; 0 prints all (default: 0)")
    analyze.add_argument("--color", choices=("never",), default="always",
                         help="Disable ANSI colors (colors are enabled by default)")
    ns = parser.parse_args()
    if ns.command == "collect" and ns.host_check_timeout < 1:
        ap.error("--host-check-timeout must be at least 1 second")

    if ns.command == "analyze":
        if ns.limit < 0:
            analyze.error("--limit cannot be negative")
        return analyze_graph_files(ns.json_files, ns.from_user, ns.limit, ns.color)

    if ns.command == "graph":
        if ns.action == "start":
            return _start_graph_server(ns.bind, ns.port, ns.input, ns.verbose)
        if ns.action == "stop":
            return _stop_graph_server(ns.bind, ns.port)
        if ns.action == "status":
            pid_file = _graph_pid_file(ns.bind, ns.port)
            pid = _read_graph_pid(pid_file)
            if pid and _graph_daemon_matches(pid):
                print(f"[+] DACLhound graph running at http://{ns.bind}:{ns.port}/ (PID {pid})")
            else:
                pid_file.unlink(missing_ok=True)
                print(f"[i] No DACLhound background server found for {ns.bind}:{ns.port}")
            return 0
        from daclgraph_server import run_server

        if ns._daemon_child:
            def stop_daemon(_signum, _frame):
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, stop_daemon)
        try:
            run_server(ns.bind, ns.port, ns.input, ns.verbose)
        finally:
            if ns._daemon_child and ns._pid_file:
                pid_file = Path(ns._pid_file)
                if _read_graph_pid(pid_file) == os.getpid():
                    pid_file.unlink(missing_ok=True)
        return 0

    type_map = {"users": ("user", "(|(&(objectCategory=person)(objectClass=user))(objectClass=msDS-GroupManagedServiceAccount))"),
                "groups": ("group", "(objectCategory=group)"),
                "computers": ("computer", "(objectCategory=computer)"),
                "ous": ("ou", "(objectClass=organizationalUnit)"),
                "containers": ("container", "(objectClass=container)"),
                "gpos": ("gpo", "(objectClass=groupPolicyContainer)"),
                "domain": ("domain", "(objectClass=domainDNS)"),
                "trusts": ("trusted_domain", "(objectClass=trustedDomain)"),
                "sites": ("site", "(objectClass=site)"),
                "foreign-security-principals": ("foreign_security_principal", "(objectClass=foreignSecurityPrincipal)")}
    requested = {x.strip().lower() for x in ns.types.split(",") if x.strip()}
    unknown = requested - (set(type_map) | {"adcs"})
    if unknown or not requested:
        ap.error(f"invalid object types: {', '.join(sorted(unknown or requested))}")
    kerberos_ticket = None
    env_ccache = os.environ.get("KRB5CCNAME", "")
    kerberos_enabled = bool(ns.aes_key) or ns.kerberos is not None or ns.no_pass or (
        not ns.password and not ns.nt_hash and bool(env_ccache)
    )
    auth_secret = ns.aes_key or ns.password
    if ns.aes_key and (ns.password or ns.nt_hash or ns.kerberos is not None):
        ap.error("use -aesKey on its own for AES Kerberos authentication")
    if ns.password and ns.nt_hash:
        ap.error("choose either -p or -hashes")
    if ns.no_pass and (ns.password or ns.nt_hash):
        ap.error("-no-pass cannot be combined with -p or -hashes")
    if ns.nt_hash:
        supplied_hash = ns.nt_hash.strip()
        if ":" in supplied_hash:
            lm_hash, nt_hash = supplied_hash.split(":", 1)
            valid_lm = not lm_hash or (len(lm_hash) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", lm_hash))
            valid_nt = len(nt_hash) == 32 and bool(re.fullmatch(r"[0-9a-fA-F]{32}", nt_hash))
            if not (valid_lm and valid_nt):
                ap.error("-hashes must be a 32-character NTHASH or LMHASH:NTHASH")
            auth_secret = nt_hash if kerberos_enabled else f"{lm_hash}:{nt_hash}"
        elif len(supplied_hash) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", supplied_hash):
            auth_secret = supplied_hash if kerberos_enabled else f":{supplied_hash}"
        else:
            ap.error("-hashes must be a 32-character NTHASH or LMHASH:NTHASH")
    if ns.kerberos is not None:
        ccache = ns.kerberos or (env_ccache if not ns.password and not ns.nt_hash else "")
        if ccache and (ns.password or ns.nt_hash):
            ap.error("use either a Kerberos ccache with -k, or combine -k with -p/-hashes")
        if not ccache and not ns.password and not ns.nt_hash:
            ap.error("-k needs a ccache path, KRB5CCNAME, or -p for Kerberos authentication")
        if ccache:
            if ccache.startswith("ccache="):
                ccache = ccache[7:]
            if ccache.startswith("FILE:"):
                ccache = ccache[5:]
            if ":" in ccache and not re.match(r"^[A-Za-z]:[\\/]", ccache):
                ap.error("-k supports a ccache file path (or KRB5CCNAME=FILE:path)")
            kerberos_ticket = str(Path(ccache).expanduser().resolve())
    elif not ns.password and not ns.nt_hash and not ns.aes_key and env_ccache:
        ccache = env_ccache[5:] if env_ccache.startswith("FILE:") else env_ccache
        if ccache.startswith("ccache="):
            ccache = ccache[7:]
        kerberos_ticket = str(Path(ccache).expanduser().resolve())
    if ns.no_pass and not kerberos_ticket:
        ap.error("-no-pass requires a ccache path with -k or KRB5CCNAME")
    requested_objects = requested - {"adcs"}
    if ns.no_adcs and "adcs" in requested:
            ap.error("--no-adcs cannot be combined with 'adcs' in -t/--types")
    include_adcs = not ns.no_adcs
    selected = {type_map[t][0] for t in requested_objects}
    attrs = ("distinguishedName,sAMAccountName,objectClass,objectSid,sIDHistory,nTSecurityDescriptor,memberOf,member,altSecurityIdentities,description,homeDirectory,whenCreated,pwdLastSet,lastLogon,lastLogonTimestamp,ms-DS-MachineAccountQuota,"
             "primaryGroupID,tokenGroups,tokenGroupsNoGCAcceptable,cn,name,displayName,gPLink,gPOptions,gPCFileSysPath,gPCWQLFilter,versionNumber,"
             "userAccountControl,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity,msDS-GroupMSAMembership,"
             "servicePrincipalName,dNSHostName,adminCount,trustPartner,trustDirection,trustType,trustAttributes,securityIdentifier,scriptPath,operatingSystem,operatingSystemVersion")
    raw_entries: list[dict[str, Any]] = []
    used_adws = False
    if ns.from_raw:
        try:
            loaded = json.loads(Path(ns.from_raw).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not read raw JSON {ns.from_raw}: {exc}") from exc
        if not isinstance(loaded, list):
            raise RuntimeError("The --from-raw file must contain a JSON list")
        raw_entries = [x for x in loaded if isinstance(x, dict)]
    else:
        def collect_adws() -> list[dict[str, Any]]:
            from .adws.collector import ADWSCollector
            kerberos_ccache = None
            kdc_host = None
            if kerberos_enabled or ns.aes_key:
                if not ns.username and not kerberos_ticket:
                    raise RuntimeError("native ADWS Kerberos requires -u and either a ccache or Kerberos credentials")
                if not kerberos_ticket:
                    if not ns.username:
                        raise RuntimeError("native ADWS Kerberos needs -u when obtaining a ticket from a password or key")
                    from .collector import kerberos_kdc_for_user_realm, request_tgt_ccache_data
                    kdc_host = kerberos_kdc_for_user_realm(ns.domain, ns.host, ns.dc_ip)
                    kerberos_ccache = request_tgt_ccache_data(
                        ns.username, ns.domain, kdc_host,
                        password=ns.password,
                        nt_hash=(auth_secret if ns.nt_hash else None),
                        aes_key=ns.aes_key,
                    )
                else:
                    from .collector import kerberos_kdc_for_user_realm
                    kdc_host = kerberos_kdc_for_user_realm(ns.domain, ns.host, ns.dc_ip)
                collector = ADWSCollector(
                    ns.host, ns.domain, ns.username or "", None, timeout=ns.timeout, dc_ip=ns.dc_ip,
                    kerberos=True, kerberos_ticket=kerberos_ticket,
                    kerberos_ccache=kerberos_ccache, kdc_host=kdc_host,
                )
                return collector.collect(requested_objects, type_map, attrs, include_adcs)
            secret = auth_secret if ns.password else None
            hashes = auth_secret if ns.nt_hash else None
            if not ns.username or not (secret or hashes):
                raise RuntimeError("native ADWS requires -u and either -p or -hashes")
            collector = ADWSCollector(ns.host, ns.domain, ns.username, secret,
                                      hashes=hashes, timeout=ns.timeout, dc_ip=ns.dc_ip)
            return collector.collect(requested_objects, type_map, attrs, include_adcs)

        if ns.transport == "adws":
            auth_mode = "Kerberos" if kerberos_enabled or ns.aes_key else "NTLM"
            print(_status("*", f"Authentication: {auth_mode}; transport: ADWS", "1;34"), file=sys.stderr)
            try:
                raw_entries = collect_adws()
                used_adws = True
            except Exception as exc:
                raise RuntimeError(f"native ADWS collection failed: {exc}") from exc
        else:
            try:
                ensure_bloodyad_available()
                raw_entries = asyncio.run(collect_with_bloodyad(
                    ns.host, ns.domain, ns.username, auth_secret, kerberos_ticket,
                    requested_objects, type_map, attrs, ns.timeout, ns.dc_ip, include_adcs,
                    ns.secure, kerberos_enabled,
                    "aes" if ns.aes_key else "rc4" if ns.nt_hash and kerberos_enabled else "",
                ))
            except Exception as exc:
                network_failure = any(token in str(exc).casefold() for token in (
                    "timed out", "timeout", "connection refused", "no route", "network is unreachable",
                    "ldap server unavailable", "cannot connect", "connection failed", "connect call failed",
                    "connection reset", "errno 111", "getaddrinfo",
                    "name or service not known", "bloodyad python package is missing",
                ))
                if ns.transport != "auto" or ns.secure or not network_failure:
                    raise RuntimeError(f"LDAP collection failed: {exc}") from exc
                print(f"[!] LDAP connection failed ({exc}); retrying collection through native ADWS", file=sys.stderr)
                try:
                    raw_entries = collect_adws()
                    used_adws = True
                except Exception as adws_exc:
                    raise RuntimeError(f"LDAP was unavailable and native ADWS collection also failed: {adws_exc}") from adws_exc

    if not include_adcs:
        raw_entries = [entry for entry in raw_entries if not entry.get("__daclgraph_adcs_kind")]

    # Deduplicate across class filters by object SID/DN while keeping original bloodyAD output.
    unique: dict[str, dict[str, Any]] = {}
    for e in raw_entries:
        unique[stable_id(e) or json.dumps(e, sort_keys=True)] = e
    raw_entries = list(unique.values())
    if ns.host_checks:
        collect_host_service_checks(
            raw_entries, username=ns.username or "", domain=ns.domain,
            password=ns.password or "", hashes=ns.nt_hash or "", aes_key=ns.aes_key or "",
            kerberos=kerberos_enabled or bool(ns.aes_key), ccache=kerberos_ticket,
            kdc_host=ns.dc_ip or ns.host, dns_server=ns.dns_server or ns.dc_ip,
            timeout=ns.host_check_timeout,
        )
    target_domain = _target_domain(raw_entries, ns.domain)
    dataset = build_dataset(raw_entries, target_domain, selected)
    out, raw_path = _resolve_output_paths(target_domain, ns.output, ns.raw_output, ns.overwrite)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dataset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if raw_path is not None:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(json.dumps(raw_entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _print_collection_summary(dataset, out)
    if used_adws:
        print(_status("*", "Need to exploit over ADWS, for example when LDAP is unavailable? SOAPy supports targeted operations such as RBCD, Shadow Credentials, and SPN/UAC writes: https://github.com/logangoins/SOAPy", "1;34"))
    if raw_path:
        print(f"[+] Raw collector response: {raw_path}")
    return 0


def entrypoint() -> int:
    """Console-script entry point with concise CLI errors."""
    try:
        return main()
    except (RuntimeError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
