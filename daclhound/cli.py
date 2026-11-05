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
    collect_with_bloodyad,
    ensure_bloodyad_available,
)
from .common import classify, stable_id
from .graph_control import (
    _graph_daemon_matches,
    _graph_pid_file,
    _read_graph_pid,
    _start_graph_server,
    _stop_graph_server,
)
from .server import run_server


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect, analyze, or graph Active Directory DACL data.")
    parser.add_argument("--version", action="version", version=f"DACLhound {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    ap = commands.add_parser(
        "collect", description="Read-only Active Directory DACL collector powered by bloodyAD.",
        help="Collect DACLs and write a normalized graph JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  DACLhound.py collect --host $FQDN -d $DOMAIN -u \'user\' -p \'password\' --dc-ip $IP --output "$DOMAIN".json',
    )
    auth = ap.add_argument_group("authentication")
    auth.add_argument("-H", "--host", required=True, help="Domain controller hostname or IP")
    auth.add_argument("-d", dest="domain", required=True, metavar="DOMAIN", help="Domain used for authentication")
    auth.add_argument("-u", dest="username", metavar="USERNAME",
                      help="Username used for NTLM authentication")
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
    collection.add_argument("--types", default="users,groups,computers,ous,containers,gpos,domain,trusts",
                            help="Comma-separated object types: users, groups, computers, OUs, containers, GPOs, domain, trusts")
    collection.add_argument("--no-adcs", action="store_true", help="Skip native ADCS ESC collection (enabled by default)")

    output = ap.add_argument_group("output")
    output.add_argument("-o", "--output", default="daclgraph.json", help="Path for normalized graph JSON")
    output.add_argument("--raw-output", nargs="?", const="", metavar="FILE",
                        help="Also save raw bloodyAD data (optional; defaults to OUTPUT.raw.json)")
    output.add_argument("--from-raw", help="Build the graph from an existing raw JSON file without querying LDAP")

    connection = ap.add_argument_group("connection and diagnostics")
    connection.add_argument("-i", "--dc-ip", help="Domain controller IP when -H is a hostname")
    connection.add_argument("-s", "--secure", action="store_true", help="Use LDAPS")
    connection.add_argument("-t", "--timeout", type=int, default=180, help="LDAP connection timeout in seconds")
    connection.add_argument("-v", "--verbose", action="count", default=0,
                            help="Show additional collection details; repeat for more detail")
    graph = commands.add_parser(
        "graph", help="Serve a graph JSON in the interactive web viewer",
        description="Run the graph viewer in this terminal or manage it as a background service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  DACLhound.py graph start --input <domain>.json\n"
                "  DACLhound.py graph stop\n"
                "  DACLhound.py graph --input <domain>.json  # foreground; stop with Ctrl+C\n"
                "  DACLhound.py graph --verbose             # print HTTP request logs"),
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
                "trusts": ("trusted_domain", "(objectClass=trustedDomain)")}
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
    attrs = ("distinguishedName,sAMAccountName,objectClass,objectSid,sIDHistory,nTSecurityDescriptor,memberOf,member,altSecurityIdentities,description,"
             "primaryGroupID,cn,name,displayName,gPLink,gPOptions,gPCFileSysPath,gPCWQLFilter,versionNumber,"
             "userAccountControl,msDS-AllowedToDelegateTo,msDS-AllowedToActOnBehalfOfOtherIdentity,msDS-GroupMSAMembership,"
             "servicePrincipalName,dNSHostName,adminCount,trustPartner,trustDirection,trustType,trustAttributes,securityIdentifier")
    raw_entries: list[dict[str, Any]] = []
    if ns.from_raw:
        try:
            loaded = json.loads(Path(ns.from_raw).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not read raw JSON {ns.from_raw}: {exc}") from exc
        if not isinstance(loaded, list):
            raise RuntimeError("The --from-raw file must contain a JSON list")
        raw_entries = [x for x in loaded if isinstance(x, dict)]
    else:
        ensure_bloodyad_available()
        if ns.verbose:
            auth_mode = ("Kerberos AES key" if ns.aes_key else "Kerberos ccache" if kerberos_ticket else "Kerberos password" if ns.kerberos is not None and ns.password
                         else "Kerberos" if ns.kerberos is not None else "NTLM hash" if ns.nt_hash
                         else "NTLM password" if ns.password else "integrated/default")
            print(f"[*] Authentication: {auth_mode}; LDAP security: {'LDAPS' if ns.secure else 'LDAP'}", file=sys.stderr)
            if ns.verbose > 1 and kerberos_ticket:
                print(f"[*] Kerberos ccache: {kerberos_ticket}", file=sys.stderr)
        try:
            raw_entries = asyncio.run(collect_with_bloodyad(
                ns.host, ns.domain, ns.username, auth_secret, kerberos_ticket,
                requested_objects, type_map, attrs, ns.timeout, ns.dc_ip, include_adcs,
                ns.secure, kerberos_enabled,
                "aes" if ns.aes_key else "rc4" if ns.nt_hash and kerberos_enabled else "",
            ))
        except Exception as exc:
            raise RuntimeError(f"bloodyAD library collection failed: {exc}") from exc

    if not include_adcs:
        raw_entries = [entry for entry in raw_entries if not entry.get("__daclgraph_adcs_kind")]

    # Deduplicate across class filters by object SID/DN while keeping original bloodyAD output.
    unique: dict[str, dict[str, Any]] = {}
    for e in raw_entries:
        unique[stable_id(e) or json.dumps(e, sort_keys=True)] = e
    raw_entries = list(unique.values())
    dataset = build_dataset(raw_entries, ns.domain, selected)
    out = Path(ns.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dataset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    raw_path = None
    if ns.raw_output is not None:
        raw_path = Path(ns.raw_output) if ns.raw_output else out.with_name(out.stem + ".raw.json")
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(json.dumps(raw_entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Objects: {dataset['stats']['objects']} | ACEs: {dataset['stats']['aces']} | Trustees: {dataset['stats']['trustees']} | ADCS findings: {dataset['stats']['adcsFindings']}")
    print(f"[+] Graph: {out}")
    if raw_path:
        print(f"[+] Raw bloodyAD response: {raw_path}")
    return 0


def entrypoint() -> int:
    """Console-script entry point with concise CLI errors."""
    try:
        return main()
    except (RuntimeError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
