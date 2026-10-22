#!/usr/bin/env python3
"""Read AD security descriptors through bloodyAD and build a local graph dataset."""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import importlib.util
import json
import os
import re
import sys
import signal
import socket
import subprocess
import time
import base64
import hashlib
from pathlib import Path
from typing import Any

__version__ = "0.1.6"


def ensure_bloodyad_available() -> None:
    """Require bloodyAD as an installed Python library, never as a subprocess."""
    if importlib.util.find_spec("bloodyAD") is None:
        raise RuntimeError("bloodyAD Python package is missing; activate the project venv and install requirements.txt")


def patch_badldap_rfc4515_compat() -> None:
    """Fix badldap's escaped-filter decoder on Python 3.10 (int.to_bytes needs length)."""
    from badldap.protocol import query as badldap_query

    def rfc4515_encode(value: str) -> bytes:
        i = 0
        byte_str = bytearray()
        while i < len(value):
            if value[i] == "\\" and i < len(value) - 2:
                try:
                    byte_str.append(int(value[i + 1 : i + 3], 16))
                    i += 2
                except ValueError:
                    byte_str.extend(b"\\")
            else:
                byte_str.extend(value[i].encode())
            i += 1
        return bytes(byte_str)

    badldap_query.rfc4515_encode = rfc4515_encode


def json_value(value: Any) -> Any:
    """Match bloodyAD's JSON conversion for values returned by its search renderer."""
    if isinstance(value, dict):
        return {key: json_value(member) for key, member in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_value(member) for member in value]
    return str(value)


async def collect_with_bloodyad(
    host: str,
    domain: str,
    username: str | None,
    password: str | None,
    kerberos_ticket: str | None,
    requested: set[str],
    type_map: dict[str, tuple[str, str]],
    attrs: str,
    timeout: int,
    dc_ip: str | None = None,
    include_adcs: bool = False,
    secure: bool = False,
    kerberos: bool = False,
    auth_format: str = "",
) -> list[dict[str, Any]]:
    patch_badldap_rfc4515_compat()
    from bloodyAD.cli_modules.get import search as bloodyad_search
    from bloodyAD.exceptions import NoResultError
    from bloodyAD.network.config import Config, ConnectionHandler

    krb_args = ([f"ccache={kerberos_ticket}"] if kerberos_ticket else []) if kerberos else None
    config = Config(host=host, domain=domain, username=username or "", password=password or "",
                    krb_args=krb_args, dcip=dc_ip or "", timeout=timeout,
                    scheme="ldaps" if secure else "ldap", format=auth_format)
    conn = ConnectionHandler(config=config)
    entries: list[dict[str, Any]] = []
    try:
        for kind in sorted(requested):
            _, ldap_filter = type_map[kind]
            print(f"[*] Collecting {kind} DACLs from {host}", file=sys.stderr)
            async for entry in bloodyad_search(conn, base="DOMAIN", filter=ldap_filter,
                                               attr=attrs, resolve_sd=True):
                entries.append(json_value(entry))
        if include_adcs:
            adcs_attrs = (
                "distinguishedName,objectClass,objectSid,cn,name,displayName,nTSecurityDescriptor,"
                "pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,"
                "msPKI-RA-Signature,msPKI-RA-Application-Policies,msPKI-Template-Schema-Version,"
                "msPKI-Certificate-Application-Policy,msPKI-Certificate-Policy,msPKI-RA-Policies,"
                "msPKI-Private-Key-Flag,msPKI-Cert-Template-OID,"
                "msPKI-Template-Minor-Revision,msDS-OIDToGroupLink,certificateTemplates,"
                "dNSHostName,cACertificate,flags,altSecurityIdentities"
            )
            try:
                ldap = await conn.getLdap()

                async def collect_adcs(label: str, base: str, ldap_filter: str,
                                       kind: str, query_attrs: str = adcs_attrs,
                                       resolve_sd: bool = True) -> None:
                    print(f"[*] Collecting ADCS {label} from {host}", file=sys.stderr)
                    try:
                        async for entry in bloodyad_search(
                            conn, base=base, filter=ldap_filter,
                            attr=query_attrs, resolve_sd=resolve_sd,
                        ):
                            item = json_value(entry)
                            item["__daclgraph_adcs_kind"] = kind
                            entries.append(item)
                    except NoResultError as exc:
                        if str(exc.base).casefold() == base.casefold() and exc.filter == ldap_filter:
                            print(f"[i] No ADCS {label} found; continuing", file=sys.stderr)
                        else:
                            print(f"[!] ADCS {label} collection warning: {exc}; continuing", file=sys.stderr)
                    except Exception as exc:
                        print(f"[!] ADCS {label} collection warning: {exc}; continuing", file=sys.stderr)

                await collect_adcs("certificate templates", ldap.configNC,
                                   "(objectClass=pKICertificateTemplate)", "template")
                await collect_adcs("enterprise CAs", ldap.configNC,
                                   "(objectClass=pKIEnrollmentService)", "ca")
                rootca_base = "CN=Certification Authorities,CN=Public Key Services,CN=Services," + ldap.configNC
                await collect_adcs("root CAs", rootca_base,
                                   "(objectClass=certificationAuthority)", "rootca")
                await collect_adcs("issuance policy OIDs", ldap.configNC,
                                   "(objectClass=msPKI-Enterprise-Oid)", "oid")
                pki_base = "CN=Public Key Services,CN=Services," + ldap.configNC
                await collect_adcs("PKI containers", pki_base,
                                   "(objectClass=container)", "pki_object")
                ntauth_dn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + ldap.configNC
                await collect_adcs("NTAuth store", ntauth_dn, "(objectClass=*)", "ntauth",
                                   "distinguishedName,cACertificate", resolve_sd=False)
            except Exception as exc:
                print(f"[!] ADCS collection warning: {exc}; continuing with collected DACL data",
                      file=sys.stderr)
    finally:
        await conn.closeLdap()
    return entries


def scalar(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(scalar(x) for x in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return "" if value is None else str(value)


def classify(entry: dict[str, Any]) -> str:
    classes = entry.get("objectClass", [])
    if not isinstance(classes, list):
        classes = [classes]
    normalized = {scalar(c).lower() for c in classes}
    if "grouppolicycontainer" in normalized:
        return "gpo"
    if "organizationalunit" in normalized:
        return "ou"
    if "container" in normalized:
        return "container"
    if "domaindns" in normalized:
        return "domain"
    if "msds-groupmanagedserviceaccount" in normalized:
        return "user"
    if "computer" in normalized:
        return "computer"
    if "group" in normalized:
        return "group"
    if "user" in normalized or "person" in normalized:
        return "user"
    return "other"


def stable_id(entry: dict[str, Any]) -> str:
    sid = scalar(entry.get("objectSid"))
    dn = scalar(entry.get("distinguishedName"))
    sam = scalar(entry.get("sAMAccountName"))
    return sid or dn or sam


def trustees(value: Any) -> list[str]:
    vals = value if isinstance(value, list) else [value]
    return sorted({scalar(v).strip() for v in vals if scalar(v).strip()})


def object_types(value: Any) -> list[str]:
    vals = value if isinstance(value, list) else [value]
    result = {part.strip() for val in vals for part in scalar(val).split(";") if part.strip()}
    return sorted(result) or ["Self"]


def attr(entry: dict[str, Any], name: str, default: Any = None) -> Any:
    """LDAP attributes are case-insensitive; raw bloodyAD keys are not."""
    wanted = name.casefold()
    return next((value for key, value in entry.items() if key.casefold() == wanted), default)


def canonical_sid(value: Any) -> str:
    """Convert a rendered SID or base64 binary SID to canonical text."""
    text = scalar(value).strip()
    if re.fullmatch(r"S-\d-\d+(?:-\d+)+", text, re.IGNORECASE):
        return text.upper()
    try:
        raw = base64.b64decode(text, validate=True)
        if len(raw) < 8:
            return ""
        revision, count = raw[0], raw[1]
        if len(raw) != 8 + count * 4:
            return ""
        authority = int.from_bytes(raw[2:8], "big")
        subs = [int.from_bytes(raw[8 + i * 4:12 + i * 4], "little") for i in range(count)]
        return "S-" + "-".join(map(str, [revision, authority, *subs]))
    except (ValueError, TypeError):
        return ""


def int_attr(entry: dict[str, Any], name: str) -> int | None:
    value = attr(entry, name)
    try:
        return int(scalar(value), 0)
    except (TypeError, ValueError):
        return None


def adcs_enrollers(entry: dict[str, Any], *, include_common: bool = False) -> set[str]:
    """Return trustees with an allow enrollment ACE or full control on an ADCS object."""
    descriptor = attr(entry, "nTSecurityDescriptor", {}) or {}
    if isinstance(descriptor, list):
        descriptor = descriptor[0] if descriptor else {}
    if not isinstance(descriptor, dict):
        return set()
    result: set[str] = set()
    for ace in descriptor.get("ACL", []) or []:
        if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
            continue
        rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
        object_type = scalar(ace.get("ObjectType")).casefold().replace("_", "-")
        enroll_right = (
            "CONTROL_ACCESS" in rights
            and any(token in object_type for token in ("certificate-enrollment", "enroll", "all-extended-rights"))
        ) or (
            "WRITE_PROP" in rights and "certificate-enrollment" in object_type
        )
        if enroll_right or "GENERIC_ALL" in rights:
            result.update(
                t.casefold() for t in trustees(ace.get("Trustee"))
                if include_common or not adcs_common_principal(t)
            )
    return result


def adcs_eku(entry: dict[str, Any]) -> set[str]:
    value = attr(entry, "pKIExtendedKeyUsage", []) or []
    values = value if isinstance(value, list) else [value]
    return {scalar(item).strip() for item in values if scalar(item).strip()}


AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4", "1.3.6.1.4.1.311.20.2.2"}
ANY_PURPOSE_EKU = "2.5.29.37.0"
ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"
COMMON_ADCS_PRINCIPALS = {
    "everyone", "authenticated_users", "authenticated users", "principal_self", "principal self",
    "creator_owner", "creator owner", "local_system", "local system", "nt authority\\system",
    "builtin_administrators", "builtin administrators", "administrators", "account_operators",
    "account operators", "domain admins", "enterprise admins", "schema admins",
    "enterprise read-only domain controllers", "enterprise_read_only_domain_controllers",
    "enterprise_domain_controllers", "enterprise domain controllers", "alias_prew2kcompacc",
    "pre-windows 2000 compatible access", "ras and ias servers", "windows_authorization_access_group",
    "windows authorization access group", "terminal_server_license_servers", "terminal server license servers",
    "cert publishers", "key admins", "enterprise key admins", "domain users", "domain computers",
    "domain controllers", "domain guests", "read-only domain controllers", "denied rodc password replication group",
    "allowed rodc password replication group", "guests", "users", "group policy creator owners",
    "server operators", "backup operators", "print operators", "printer_operators", "replicator",
    "dnsadmins", "dnsupdateproxy",
}


def adcs_common_principal(value: str) -> bool:
    principals = [part.strip().casefold() for part in re.split(r"[;|]", value) if part.strip()]
    return bool(principals) and all(
        principal in COMMON_ADCS_PRINCIPALS
        or re.fullmatch(r"s-1-5-21-(?:\d+-){3}(?:498|512|513|514|515|516|518|519|520|521|526|527|553)", principal)
        or re.fullmatch(r"s-1-5-(?:18|19|20|32-(?:544|548|549|550|551|552|554|555|556|557|558|559|560|562|568|569|573|574|575|576|577|578|579|580|581|582|583|584|585|586|587|588|589|590|591|592|593|594|595|596|597|598|599))", principal)
        for principal in principals
    )


def adcs_cert_fingerprints(entries: list[dict[str, Any]], kind: str) -> set[str]:
    """Compare raw DER certificate bytes exposed as LDAP base64 values."""
    fingerprints: set[str] = set()
    for entry in entries:
        if entry.get("__daclgraph_adcs_kind") != kind:
            continue
        values = attr(entry, "cACertificate", []) or []
        for value in values if isinstance(values, list) else [values]:
            try:
                fingerprints.add(hashlib.sha256(base64.b64decode(scalar(value), validate=True)).hexdigest())
            except (ValueError, TypeError):
                continue
    return fingerprints


def adcs_name(entry: dict[str, Any]) -> str:
    return (scalar(attr(entry, "displayName")) or scalar(attr(entry, "cn"))
            or scalar(attr(entry, "name")) or scalar(attr(entry, "distinguishedName")) or "ADCS object")


def adcs_assessment(entries: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Summarize what this LDAP-only collection observed without treating gaps as safe."""
    templates = [e for e in entries if e.get("__daclgraph_adcs_kind") == "template"]
    cas = [e for e in entries if e.get("__daclgraph_adcs_kind") == "ca"]
    pki_objects = [e for e in entries if e.get("__daclgraph_adcs_kind") in {"pki_object", "oid"}]
    candidates = {e.get("esc") for e in edges if e.get("kind") == "adcs_esc"}
    if any(e.get("adcsEsc13") for e in edges):
        candidates.add("ESC13")

    def ace_rights(entry: dict[str, Any]) -> list[tuple[str, str, set[str], str]]:
        sd = attr(entry, "nTSecurityDescriptor", {}) or {}
        if isinstance(sd, list):
            sd = sd[0] if sd else {}
        if not isinstance(sd, dict):
            return []
        result = []
        for ace in sd.get("ACL", []) or []:
            if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                continue
            rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
            trustee = scalar(ace.get("Trustee"))
            if adcs_common_principal(trustee):
                continue
            result.append((trustee, scalar(ace.get("ObjectType")), rights,
                           scalar(ace.get("Type"))))
        return result

    write_rights = {"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER", "WRITE_PROP"}
    template_write = False
    config_attrs = ("certificate-name-flag", "enrollment-flag", "ra-signature",
                    "extendedkeyusage", "certificate-application-policy", "ra-application-policies")
    for item in templates:
        for _, scope, rights, _ in ace_rights(item):
            normalized_scope = scope.casefold().replace("_", "-")
            broad_write = bool(rights.intersection({"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"}))
            scoped_write = "WRITE_PROP" in rights and (
                normalized_scope.strip() in {"", "self"}
                or any(name in normalized_scope for name in config_attrs)
            )
            template_write |= broad_write or scoped_write
    pki_write = False
    for item in pki_objects:
        for _, scope, rights, _ in ace_rights(item):
            broad_write = bool(rights.intersection({"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"}))
            scoped_write = "WRITE_PROP" in rights and "msds-oidtogrouplink" in scope.casefold().replace("_", "-")
            pki_write |= broad_write or scoped_write
    no_security_ext = any((int_attr(t, "msPKI-Enrollment-Flag") or 0) & 0x80000 for t in templates)
    explicit_mapping = any(attr(e, "altSecurityIdentities") for e in entries)
    v1_subject_template = any(
        int_attr(t, "msPKI-Template-Schema-Version") == 1
        and bool((int_attr(t, "msPKI-Certificate-Name-Flag") or 0) & 0x1)
        for t in templates
    )
    server_auth_template = False
    for template in templates:
        ekus = adcs_eku(template)
        server_auth = "1.3.6.1.5.5.7.3.1" in ekus or ANY_PURPOSE_EKU in ekus or not ekus
        if not ((int_attr(template, "msPKI-Certificate-Name-Flag") or 0) & 0x1) or not server_auth:
            continue
        cn = scalar(attr(template, "cn")).casefold()
        for ca in cas:
            published = attr(ca, "certificateTemplates", []) or []
            names = {scalar(value).casefold() for value in (published if isinstance(published, list) else [published])}
            if cn in names and adcs_enrollers(template) & adcs_enrollers(ca):
                server_auth_template = True
                break
        if server_auth_template:
            break
    observations = {
        "ESC1": ("LDAP template, enrollment, CA publication and NTAuth signals are inspected.", "CA chain trust and effective enrollment policy still need validation."),
        "ESC2": ("Any Purpose/no-EKU templates and LDAP enrollment signals are inspected.", "The target template and effective Enrollment Agent restrictions must also be validated."),
        "ESC3": ("Enrollment Agent and authentication template signals are inspected.", "CA-side Enrollment Agent restrictions are not collected by this LDAP pass."),
        "ESC4": ("Template DACLs are inspected for write/control ACEs.", "Effective inherited rights and the exact exploitable template change need validation."),
        "ESC5": ("CA host relationships and ACLs on LDAP objects under Public Key Services are inspected.", "Whether the CA host or PKI object can be compromised from the current principal is not established by LDAP collection alone."),
        "ESC6": ("No CA EditFlags registry read is performed.", "Requires CA registry/configuration; the LDAP flags attribute is not a substitute."),
        "ESC7": ("Enterprise CA DACLs are inspected for management rights.", "CA role separation and the actual permitted CA operation require remote CA configuration."),
        "ESC8": ("No Web Enrollment endpoint or EPA probe is performed.", "Requires endpoint discovery and HTTP/NTLM/EPA validation."),
        "ESC9": ("Template NO_SECURITY_EXTENSION flag is inspected.", "Exploitability also depends on account write rights and DC certificate mapping policy."),
        "ESC10": ("No DC certificate mapping registry/policy read is performed.", "Requires DC-side mapping configuration and relevant account mapping data."),
        "ESC11": ("No ICPR/RPC encryption or relay surface probe is performed.", "Requires CA RPC configuration and network reachability checks."),
        "ESC12": ("No CA host or HSM software inventory is performed.", "This is a host/HSM-specific issue, not an LDAP-detectable directory condition."),
        "ESC13": ("Policy OIDs are correlated with authentication templates, CA publication, enrollment rights and linked groups.", "LDAP evidence establishes the directory relationship; effective group privileges and certificate authentication behavior determine impact."),
        "ESC14": ("altSecurityIdentities values are requested for collected directory objects.", "Whether a mapping is weak depends on mapping rules and the certificate identity."),
        "ESC15": ("V1 template and enrollee-supplied-subject signals are inspected.", "CA patch level is not established by LDAP and must be checked on the CA host."),
        "ESC16": ("No CA DisabledExtensions registry read is performed.", "Requires CA registry and DC strong-binding policy checks."),
        "ESC17": ("Server Authentication, subject-supply and template enrollment signals are inspected.", "A useful attack path also depends on the target service and its security impact."),
    }
    signals = {
        "ESC1": "ESC1" in candidates,
        "ESC2": "ESC2" in candidates,
        "ESC3": "ESC3" in candidates,
        "ESC4": "ESC4" in candidates or template_write,
        "ESC5": pki_write or "ESC5" in candidates,
        "ESC6": False,
        "ESC7": "ESC7" in candidates,
        "ESC8": False,
        "ESC9": no_security_ext,
        "ESC10": False,
        "ESC11": False,
        "ESC12": False,
        # Match the graph: a linked policy OID alone is not an ESC13 finding.
        # The chain must pass template, CA publication, NTAuth and enrollment checks.
        "ESC13": "ESC13" in candidates,
        "ESC14": explicit_mapping,
        "ESC15": v1_subject_template,
        "ESC16": False,
        "ESC17": server_auth_template,
    }
    remote_only = {"ESC6", "ESC8", "ESC10", "ESC11", "ESC12", "ESC16"}
    return [{"id": esc, "status": "candidate" if signals[esc] else "requires_remote_check" if esc in remote_only else "no_ldap_indicator",
             "observation": observations[esc][0], "limitation": observations[esc][1],
             "signalObserved": bool(signals[esc])}
            for esc in observations]


def add_adcs_findings(entries: list[dict[str, Any]], nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
                      object_ids: dict[str, str], domain: str) -> None:
    """Add only ESC findings; certificate templates and CA inventory stay out of the graph."""
    templates = [e for e in entries if e.get("__daclgraph_adcs_kind") == "template"]
    cas = [e for e in entries if e.get("__daclgraph_adcs_kind") == "ca"]
    rootcas = [e for e in entries if e.get("__daclgraph_adcs_kind") == "rootca"]
    pki_objects = [e for e in entries if e.get("__daclgraph_adcs_kind") in {"pki_object", "oid"}]
    ntauth = adcs_cert_fingerprints(entries, "ntauth")
    nodes_by_id = {n["id"]: n for n in nodes}
    edge_keys: set[tuple[str, str, str]] = set()
    relation_ids = {edge.get("id") for edge in edges}

    def cert_node(entry: dict[str, Any], kind: str) -> str:
        dn = scalar(attr(entry, "distinguishedName"))
        node_id = f"adcs::{kind}::{dn.casefold()}"
        if node_id not in nodes_by_id:
            label = {"template": "cert_template", "ca": "enterprise_ca",
                     "rootca": "root_ca", "ntauth": "ntauth_store"}.get(kind, "pki_object")
            node = {"id": node_id, "name": adcs_name(entry), "type": label, "dn": dn,
                    "sid": "", "owner": "", "control": "", "memberOf": [],
                    "certificateTemplates": attr(entry, "certificateTemplates", []) or [],
                    "dNSHostName": scalar(attr(entry, "dNSHostName"))}
            nodes.append(node)
            nodes_by_id[node_id] = node
        object_ids[dn.casefold()] = node_id
        object_ids[adcs_name(entry).casefold()] = node_id
        cn = scalar(attr(entry, "cn"))
        if cn:
            object_ids[cn.casefold()] = node_id
        return node_id

    def relation(kind: str, source_id: str, target_id: str, edge_type: str,
                 detail: str = "", traversable: bool = False) -> None:
        source, target = nodes_by_id.get(source_id), nodes_by_id.get(target_id)
        if not source or not target:
            return
        edge_id = f"{kind}::{source_id}::{target_id}"
        if edge_id in relation_ids:
            return
        relation_ids.add(edge_id)
        edges.append({"id": edge_id, "kind": kind, "source": source_id, "target": target_id,
                      "sourceName": source["name"], "sourceType": source["type"],
                      "targetName": target["name"], "targetType": target["type"],
                      "right": edge_type.upper(), "objectType": detail or edge_type,
                      "isACL": False, "traversable": traversable, "inherited": False})

    def certificates(entry: dict[str, Any]) -> list[Any]:
        values = attr(entry, "cACertificate", []) or []
        return values if isinstance(values, list) else [values]

    def fingerprints(entry: dict[str, Any]) -> set[str]:
        result: set[str] = set()
        for value in certificates(entry):
            try:
                der = base64.b64decode(scalar(value), validate=True)
                result.add(hashlib.sha256(der).hexdigest())
            except (ValueError, TypeError):
                continue
        return result

    def cert_subject_issuer(entry: dict[str, Any]) -> list[tuple[str, str]]:
        try:
            from cryptography import x509
        except ImportError:
            return []
        result = []
        for value in certificates(entry):
            try:
                cert = x509.load_der_x509_certificate(base64.b64decode(scalar(value), validate=True))
                result.append((cert.subject.public_bytes().hex(),
                               cert.issuer.public_bytes().hex()))
            except (ValueError, TypeError):
                continue
        return result

    template_ids = {id(entry): cert_node(entry, "template") for entry in templates}
    ca_ids = {id(entry): cert_node(entry, "ca") for entry in cas}
    root_ids = {id(entry): cert_node(entry, "rootca") for entry in rootcas}
    ntauth_entry = next((e for e in entries if e.get("__daclgraph_adcs_kind") == "ntauth"), None)

    def principal_node(principal: str) -> str:
        key = principal.casefold()
        node_id = object_ids.get(key)
        if node_id:
            return node_id
        node_id = f"trustee::{key}"
        if node_id not in nodes_by_id:
            node = {"id": node_id, "name": principal, "type": "trustee", "dn": "", "sid": "",
                    "owner": "", "control": "", "memberOf": []}
            nodes.append(node)
            nodes_by_id[node_id] = node
            object_ids[key] = node_id
        return node_id

    # Certificate-template enrollment ACEs are collected for ESC assessment,
    # but must also be represented as ordinary graph relationships. Without
    # these edges the viewer cannot show who can enroll on a template unless
    # that principal happens to trigger a separate ESC finding.
    for template in templates:
        descriptor = attr(template, "nTSecurityDescriptor", {}) or {}
        if isinstance(descriptor, list):
            descriptor = descriptor[0] if descriptor else {}
        if not isinstance(descriptor, dict):
            continue
        target_id = template_ids[id(template)]
        target_node = nodes_by_id[target_id]
        for ace_index, ace in enumerate(descriptor.get("ACL", []) or []):
            if not isinstance(ace, dict):
                continue
            rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
            object_scope = {
                value.casefold().replace("_", "-")
                for value in object_types(ace.get("ObjectType"))
            }
            if "CONTROL_ACCESS" not in rights or not any(
                "certificate-enrollment" in scope for scope in object_scope
            ):
                continue
            for trustee in trustees(ace.get("Trustee")):
                source_id = principal_node(trustee)
                source_node = nodes_by_id[source_id]
                flags = scalar(ace.get("Flags"))
                edges.append({
                    "id": f"adcs-enroll::{target_id}::{ace_index}::{source_id}",
                    "kind": "dacl", "source": source_id, "target": target_id,
                    "sourceName": source_node["name"], "sourceType": source_node["type"],
                    "targetName": target_node["name"], "targetType": target_node["type"],
                    "aceIndex": ace_index, "type": scalar(ace.get("Type")),
                    "right": scalar(ace.get("Right")), "objectType": "Certificate-Enrollment",
                    "inheritedObjectType": scalar(ace.get("InheritedObjectType")),
                    "flags": flags, "inherited": "INHERITED" in flags.upper(),
                    "raw": ace, "isACL": True,
                })

    def ca_host_node(ca: dict[str, Any]) -> dict[str, Any] | None:
        hostname = scalar(attr(ca, "dNSHostName")).strip().rstrip(".").casefold()
        if not hostname:
            return None
        shortname = hostname.split(".", 1)[0]
        for node in nodes_by_id.values():
            if node.get("type") != "computer":
                continue
            aliases = (scalar(node.get("dNSHostName")), scalar(node.get("samAccountName")),
                       scalar(node.get("name")))
            for alias in aliases:
                normalized = alias.strip().rstrip(".").casefold()
                bare = normalized.removesuffix("$")
                if normalized == hostname or bare == hostname or bare.split(".", 1)[0] == shortname:
                    return node
        return None

    def is_ca_host_principal(principal: str, ca: dict[str, Any]) -> bool:
        node = ca_host_node(ca)
        if not node:
            return False
        normalized = principal.casefold().split("\\")[-1].strip()
        if normalized == scalar(node.get("sid")).casefold():
            return True
        aliases = (scalar(node.get("name")), scalar(node.get("samAccountName")),
                   scalar(node.get("dNSHostName")))
        return any(normalized == alias.strip().rstrip(".").casefold()
                   or normalized.removesuffix("$") == alias.strip().rstrip(".").casefold().removesuffix("$")
                   for alias in aliases if alias)

    def ca_effective_enrollers(ca: dict[str, Any], candidates: set[str]) -> set[str]:
        """Keep template principals whose enrollment is allowed by the CA ACL.

        Common CA trustees such as Authenticated Users are intentionally omitted
        from graph principals, but still grant enrollment to qualifying requesters.
        """
        descriptor = attr(ca, "nTSecurityDescriptor", {}) or {}
        if isinstance(descriptor, list):
            descriptor = descriptor[0] if descriptor else {}
        if not isinstance(descriptor, dict):
            return set()
        candidate_types: dict[str, str] = {}
        for node in nodes_by_id.values():
            sid = scalar(node.get("sid")).casefold()
            node_id = scalar(node.get("id")).casefold()
            if sid:
                candidate_types[sid] = scalar(node.get("type")).casefold()
            if node_id:
                candidate_types[node_id] = scalar(node.get("type")).casefold()
        broad = {
            "everyone": "any", "s-1-1-0": "any",
            "authenticated_users": "authenticated", "authenticated users": "authenticated",
            "s-1-5-11": "authenticated",
            "domain users": "users", "s-1-5-21-domain-513": "users",
            "domain computers": "computers", "s-1-5-21-domain-515": "computers",
            "domain controllers": "computers", "s-1-5-21-domain-516": "computers",
        }
        permitted: set[str] = set()
        for ace in descriptor.get("ACL", []) or []:
            if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                continue
            rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
            scope = {value.casefold().replace("_", "-") for value in object_types(ace.get("ObjectType"))}
            has_enrollment = "GENERIC_ALL" in rights or (
                "CONTROL_ACCESS" in rights and any(
                    token in item for item in scope
                    for token in ("certificate-enrollment", "enroll", "all-extended-rights")
                )
            )
            if not has_enrollment:
                continue
            ace_trustees = {value.casefold() for value in trustees(ace.get("Trustee"))}
            for candidate in candidates:
                normalized = candidate.casefold()
                if normalized in ace_trustees:
                    permitted.add(candidate)
                    continue
                node_type = candidate_types.get(normalized, "")
                for trustee in ace_trustees:
                    trustee_scope = broad.get(trustee)
                    if trustee_scope is None and re.fullmatch(r"s-1-5-21-(?:\d+-){3}513", trustee):
                        trustee_scope = "users"
                    elif trustee_scope is None and re.fullmatch(r"s-1-5-21-(?:\d+-){3}(?:515|516)", trustee):
                        trustee_scope = "computers"
                    if trustee_scope in {"any", "authenticated"} and node_type in {"user", "computer", "group"}:
                        permitted.add(candidate)
                    elif trustee_scope == "users" and node_type in {"user", "group"}:
                        permitted.add(candidate)
                    elif trustee_scope == "computers" and node_type in {"computer", "group"}:
                        permitted.add(candidate)
        return permitted

    def add_finding(source: str, esc: str, template: dict[str, Any], ca: dict[str, Any] | None,
                    target_id: str, target_name: str, traversable: bool, evidence: list[str],
                    is_acl: bool | None = None) -> None:
        template_name = adcs_name(template)
        ca_name = adcs_name(ca) if ca else ""
        if not traversable:
            finding_id = f"adcs-finding::{esc}::{hashlib.sha1(scalar(attr(template, 'distinguishedName')).casefold().encode()).hexdigest()[:12]}"
            if finding_id not in nodes_by_id:
                finding = {"id": finding_id, "name": f"{esc} · {template_name}", "type": "adcs_finding",
                           "dn": scalar(attr(template, "distinguishedName")), "sid": "", "owner": "",
                           "control": "", "memberOf": []}
                nodes.append(finding)
                nodes_by_id[finding_id] = finding
            target_id, target_name = finding_id, nodes_by_id[finding_id]["name"]
        key = (source, esc, scalar(attr(template, "distinguishedName")).casefold())
        if key in edge_keys:
            return
        edge_keys.add(key)
        edge_id = f"adcs::{esc}::{source}::{hashlib.sha1(key[2].encode()).hexdigest()[:10]}"
        object_kind = template.get("__daclgraph_adcs_kind")
        object_label = {"ca": "Enterprise CA", "pki_object": "PKI Object", "oid": "Issuance Policy",
                        "account": "Directory Account"}.get(object_kind, "Certificate Template")
        edges.append({"id": edge_id, "kind": "adcs_esc", "esc": esc, "source": source,
                      "target": target_id, "sourceName": nodes_by_id[source]["name"],
                      "sourceType": nodes_by_id[source]["type"], "targetName": target_name,
                      "targetType": nodes_by_id.get(target_id, {}).get("type", "domain"),
                      "right": esc, "objectType": template_name, "templateName": template_name,
                      "objectLabel": object_label,
                      "isACL": esc not in {"ESC13", "ESC14"} if is_acl is None else is_acl,
                      "templateDN": scalar(attr(template, "distinguishedName")), "caName": ca_name,
                      "caDN": scalar(attr(ca, "distinguishedName")) if ca else "",
                      "traversable": traversable, "evidence": evidence})

    # ESC1 is represented as a domain path only when LDAP-visible prerequisites
    # align for the same principal on the template and its publishing CA.
    domain_dn = next((n["dn"] for n in nodes if n["type"] == "domain"), "")
    if not domain_dn:
        labels = [part for part in domain.split(".") if part]
        domain_dn = ",".join(f"DC={part}" for part in labels)
        domain_id = domain_dn
        if domain_id not in nodes_by_id:
            node = {"id": domain_id, "name": domain.upper(), "type": "domain", "dn": domain_dn,
                    "sid": "", "owner": "", "control": "", "memberOf": []}
            nodes.append(node)
            nodes_by_id[domain_id] = node
            object_ids[domain_dn.casefold()] = domain_id
    else:
        domain_id = next(n["id"] for n in nodes if n["type"] == "domain")
    domain_name = nodes_by_id[domain_id]["name"]

    # ADCS inventory relationships that are directly evidenced by LDAP values.
    for ca in cas:
        ca_id = ca_ids[id(ca)]
        ca_cert_pairs = cert_subject_issuer(ca)
        for rootca in rootcas:
            root_subjects = {subject for subject, _ in cert_subject_issuer(rootca)}
            if any(issuer in root_subjects for _, issuer in ca_cert_pairs):
                relation("enterprise_ca_for", ca_id, root_ids[id(rootca)], "EnterpriseCAFor")
    if rootcas:
        for rootca in rootcas:
            relation("root_ca_for", root_ids[id(rootca)], domain_id, "RootCAFor")

    for template in templates:
        name_flags = int_attr(template, "msPKI-Certificate-Name-Flag")
        enrollment_flags = int_attr(template, "msPKI-Enrollment-Flag") or 0
        ra_signatures = int_attr(template, "msPKI-RA-Signature") or 0
        ekus = adcs_eku(template)
        auth_eku = bool(ekus.intersection(AUTH_EKUS | {ANY_PURPOSE_EKU})) or not ekus
        template_enrollers = adcs_enrollers(template)
        # ESC4: write-level control over the template can enable a vulnerable
        # configuration. Keep this as an informational finding, not a DA path.
        descriptor = attr(template, "nTSecurityDescriptor", {}) or {}
        if isinstance(descriptor, list):
            descriptor = descriptor[0] if descriptor else {}
        for ace in (descriptor.get("ACL", []) if isinstance(descriptor, dict) else []) or []:
            if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                continue
            rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
            config_attrs = ("certificate-name-flag", "enrollment-flag", "ra-signature",
                            "extendedkeyusage", "certificate-application-policy", "ra-application-policies")
            object_scope = scalar(ace.get("ObjectType")).casefold().replace("_", "-")
            scoped_write = "WRITE_PROP" in rights and (object_scope.strip() in {"", "self"} or any(attr_name in object_scope for attr_name in config_attrs))
            if not (rights.intersection({"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"}) or scoped_write):
                continue
            for trustee in trustees(ace.get("Trustee")):
                if adcs_common_principal(trustee):
                    continue
                source = principal_node(trustee)
                add_finding(source, "ESC4", template, None, source, nodes_by_id[source]["name"], False,
                            ["Trustee has write/control rights on the certificate template DACL.",
                             "Template changes and downstream enrollment conditions require validation."])

        # ESC2 templates are valuable findings but do not by themselves create
        # an authentication path, so they are never connected to the domain.
        if ANY_PURPOSE_EKU in ekus or not ekus:
            template_cn = scalar(attr(template, "cn")).casefold()
            for ca in cas:
                published = attr(ca, "certificateTemplates", []) or []
                published_names = {scalar(x).casefold() for x in (published if isinstance(published, list) else [published])}
                if template_cn not in published_names:
                    continue
                ca_fps = adcs_cert_fingerprints([ca], "ca")
                if not ca_fps or not ntauth.intersection(ca_fps):
                    continue
                for trustee in sorted(template_enrollers & adcs_enrollers(ca)):
                    source = principal_node(trustee)
                    add_finding(source, "ESC2", template, ca, source, nodes_by_id[source]["name"], False,
                                ["Principal can enroll on the template and publishing enterprise CA.",
                                 "Template has Any Purpose EKU or no EKU; the CA certificate matches an NTAuth certificate.",
                                 "Certificate-chain trust and the ability to impersonate another identity are not established."])

        if name_flags is None or not (name_flags & 0x1) or not auth_eku:
            continue
        if enrollment_flags & 0x2 or ra_signatures != 0:
            continue
        template_cn = scalar(attr(template, "cn")).casefold()
        for ca in cas:
            published = attr(ca, "certificateTemplates", []) or []
            published_names = {scalar(x).casefold() for x in (published if isinstance(published, list) else [published])}
            if template_cn not in published_names and adcs_name(template).casefold() not in published_names:
                continue
            ca_fps = adcs_cert_fingerprints([ca], "ca")
            if not ca_fps or not ntauth.intersection(ca_fps):
                continue
            for trustee in sorted(ca_effective_enrollers(ca, template_enrollers)):
                source = principal_node(trustee)
                add_finding(source, "ESC1", template, ca, domain_id, domain_name, False,
                            ["Requester can enroll on both the template and enterprise CA.",
                             "Template permits requester-supplied subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT).",
                             "Template has an authentication-capable EKU (or no EKU).",
                             "Manager approval is disabled and no authorized signatures are required.",
                             "Template is published by this CA; its certificate matches an NTAuth certificate.",
                             "Certificate-chain trust and enrollment policy were not fully validated; shown as a candidate, not a confirmed domain path."])

    # ESC3 needs two templates: one that issues enrollment-agent certificates,
    # and one that can issue authentication certificates on behalf of another
    # identity. CA-side enrollment rights are required for both. Enrollment-agent
    # restrictions live in CA policy and are not exposed by this LDAP collector,
    # so these findings are intentionally non-traversable candidates.
    for agent_template in templates:
        if ENROLLMENT_AGENT_EKU not in adcs_eku(agent_template):
            continue
        agent_flags = int_attr(agent_template, "msPKI-Enrollment-Flag") or 0
        if agent_flags & 0x2 or (int_attr(agent_template, "msPKI-RA-Signature") or 0) != 0:
            continue
        agent_enrollers = adcs_enrollers(agent_template)
        agent_cn = scalar(attr(agent_template, "cn")).casefold()
        for ca in cas:
            published = attr(ca, "certificateTemplates", []) or []
            published_names = {scalar(x).casefold() for x in (published if isinstance(published, list) else [published])}
            if agent_cn not in published_names:
                continue
            ca_fps = adcs_cert_fingerprints([ca], "ca")
            if not ca_fps or not ntauth.intersection(ca_fps):
                continue
            agent_ca_enrollers = ca_effective_enrollers(ca, agent_enrollers)
            if not agent_ca_enrollers:
                continue
            for target_template in templates:
                target_ekus = adcs_eku(target_template)
                if not (target_ekus.intersection(AUTH_EKUS) or not target_ekus):
                    continue
                target_flags = int_attr(target_template, "msPKI-Enrollment-Flag") or 0
                if target_flags & 0x2 or (int_attr(target_template, "msPKI-RA-Signature") or 0) != 0:
                    continue
                target_cn = scalar(attr(target_template, "cn")).casefold()
                if target_cn not in published_names:
                    continue
                principals = ca_effective_enrollers(
                    ca, agent_enrollers & adcs_enrollers(target_template)
                )
                for trustee in sorted(principals):
                    source = principal_node(trustee)
                    add_finding(source, "ESC3", target_template, ca, domain_id, domain_name, False,
                                [f"Principal can enroll on enrollment-agent template {adcs_name(agent_template)}.",
                                 f"Principal can enroll on authentication template {adcs_name(target_template)} and this CA.",
                                 "Both templates are published; the CA certificate matches an NTAuth certificate.",
                                 "Neither template has manager approval or an authorized-signature requirement.",
                                 "Certificate-chain trust and enrollment-agent restrictions are CA policy and were not fully collected; validate before assessing exploitability."])

    # LDAP-visible indicators for additional ESCs are shown as candidate findings
    # only. They are deliberately non-traversable until CA/DC/host prerequisites
    # have been collected and validated.
    def emit_indicator(esc: str, item: dict[str, Any], principal: str, evidence: list[str],
                       ca: dict[str, Any] | None = None, is_acl: bool | None = None) -> None:
        if adcs_common_principal(principal):
            return
        source = principal_node(principal)
        add_finding(source, esc, item, ca, source, nodes_by_id[source]["name"], False, evidence, is_acl)

    def published_enrollers(template: dict[str, Any], *, include_common: bool = False) -> list[tuple[dict[str, Any], set[str]]]:
        cn = scalar(attr(template, "cn")).casefold()
        result = []
        for ca in cas:
            raw_names = attr(ca, "certificateTemplates", []) or []
            names = {scalar(value).casefold() for value in (raw_names if isinstance(raw_names, list) else [raw_names])}
            if cn in names:
                principals = ca_effective_enrollers(
                    ca, adcs_enrollers(template, include_common=include_common)
                )
                if principals:
                    result.append((ca, principals))
        return result

    for item in pki_objects:
        if item.get("__daclgraph_adcs_kind") != "pki_object":
            continue
        sd = attr(item, "nTSecurityDescriptor", {}) or {}
        if isinstance(sd, list):
            sd = sd[0] if sd else {}
        if not isinstance(sd, dict):
            continue
        for ace in sd.get("ACL", []) or []:
            if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                continue
            rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
            scope = scalar(ace.get("ObjectType")).casefold().replace("_", "-")
            relevant_write = rights.intersection({"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"})
            relevant_write |= {"WRITE_PROP"} if "msds-oidtogrouplink" in scope else set()
            if not relevant_write:
                continue
            for trustee in trustees(ace.get("Trustee")):
                emit_indicator("ESC5", item, trustee,
                               [f"An allow ACE grants {scalar(ace.get('Right'))} on a container below Public Key Services.",
                                "This is an LDAP-visible PKI object-control indicator; the affected PKI configuration and impact need review."])

    for ca in cas:
        host_node = ca_host_node(ca)
        if host_node:
            host_principal = scalar(host_node.get("samAccountName")) or scalar(host_node.get("name"))
            emit_indicator(
                "ESC5", ca, host_principal,
                [f"Enterprise CA {adcs_name(ca)} is registered on host {scalar(attr(ca, 'dNSHostName'))}.",
                 "Compromise of the CA host (for example, local administrative control) can expose the CA and its PKI; host compromise is not verified by this LDAP collection."],
                ca, is_acl=False,
            )
        sd = attr(ca, "nTSecurityDescriptor", {}) or {}
        if isinstance(sd, list):
            sd = sd[0] if sd else {}
        if not isinstance(sd, dict):
            continue
        for ace in sd.get("ACL", []) or []:
            if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                continue
            rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
            scope = scalar(ace.get("ObjectType")).casefold().replace("_", "-")
            manages_ca = bool(rights.intersection({"GENERIC_ALL", "MANAGE_CA", "MANAGE_CERTIFICATES"}))
            manages_ca |= "CONTROL_ACCESS" in rights and any(x in scope for x in ("manage-ca", "manage-certificates", "issue-and-manage"))
            if manages_ca:
                for trustee in trustees(ace.get("Trustee")):
                    # The CA host's own account-to-CA relationship is represented
                    # as the ESC5 host compromise prerequisite above, not ESC7.
                    if is_ca_host_principal(trustee, ca):
                        continue
                    emit_indicator("ESC7", ca, trustee,
                                   [f"An allow ACE grants {scalar(ace.get('Right'))} on enterprise CA {adcs_name(ca)}.",
                                    "The trustee is not the CA host account; CA role separation, configuration, and the exact management operation still require validation."], ca)

    for template in templates:
        name_flags = int_attr(template, "msPKI-Certificate-Name-Flag") or 0
        enrollment_flags = int_attr(template, "msPKI-Enrollment-Flag") or 0
        schema_version = int_attr(template, "msPKI-Template-Schema-Version")
        ekus = adcs_eku(template)
        published = published_enrollers(template)
        if enrollment_flags & 0x80000:
            for ca, principals in published:
                for trustee in sorted(principals):
                    emit_indicator("ESC9", template, trustee,
                                   ["Template has CT_FLAG_NO_SECURITY_EXTENSION and is published by this enterprise CA.",
                                    "Account write rights and the domain controllers' certificate mapping policy were not validated."], ca)
        if schema_version == 1 and name_flags & 0x1 and not (enrollment_flags & 0x2) and (int_attr(template, "msPKI-RA-Signature") or 0) == 0:
            for ca, principals in published:
                for trustee in sorted(principals):
                    emit_indicator("ESC15", template, trustee,
                                   ["Template is schema version 1, is published by this CA, and permits enrollee-supplied subject without approval/signature requirements.",
                                    "The CA patch level for CVE-2024-49019 is not available through this LDAP collection."], ca)
        server_auth = "1.3.6.1.5.5.7.3.1" in ekus or ANY_PURPOSE_EKU in ekus or not ekus
        if name_flags & 0x1 and server_auth and not (enrollment_flags & 0x2) and (int_attr(template, "msPKI-RA-Signature") or 0) == 0:
            for ca, principals in published:
                for trustee in sorted(principals):
                    emit_indicator("ESC17", template, trustee,
                                   ["Template is published by this CA, permits enrollee-supplied subject and includes Server Authentication EKU.",
                                    "A useful impact depends on an impersonable target service; service configuration was not collected."], ca)

    # ESC13 is represented as a compact graph chain: enrollee -> finding ->
    # OID-linked group. Template and policy details stay on the finding metadata.
    oid_by_value: dict[str, dict[str, Any]] = {}
    for oid in (e for e in pki_objects if e.get("__daclgraph_adcs_kind") == "oid"):
        oid_value = scalar(attr(oid, "msPKI-Cert-Template-OID")).strip().casefold()
        if oid_value:
            oid_by_value[oid_value] = oid

    for template in templates:
        ekus = adcs_eku(template)
        if not (ekus.intersection(AUTH_EKUS | {ANY_PURPOSE_EKU}) or not ekus):
            continue
        enrollment_flags = int_attr(template, "msPKI-Enrollment-Flag") or 0
        if enrollment_flags & 0x2 or (int_attr(template, "msPKI-RA-Signature") or 0) != 0:
            continue
        raw_policies = attr(template, "msPKI-Certificate-Policy", []) or []
        policies = raw_policies if isinstance(raw_policies, list) else [raw_policies]
        for policy in policies:
            policy_oid = scalar(policy).strip()
            oid = oid_by_value.get(policy_oid.casefold())
            if not oid:
                continue
            group_dn = scalar(attr(oid, "msDS-OIDToGroupLink")).strip()
            if not group_dn:
                continue
            group_id = object_ids.get(group_dn.casefold())
            if not group_id:
                # Some bloodyAD versions return the linked principal as a name
                # instead of a DN; try the CN as a fallback before creating a
                # placeholder node.
                cn_match = re.search(r"(?:^|,)CN=([^,]+)", group_dn, re.IGNORECASE)
                group_id = object_ids.get(cn_match.group(1).casefold()) if cn_match else None
            group_id = group_id or principal_node(group_dn)
            group_node = nodes_by_id[group_id]
            eligible_cas: list[tuple[dict[str, Any], set[str]]] = []
            # ESC13 depends on every principal that can enroll. Broad groups
            # (for example Domain Users) are often the actual attack entrypoint,
            # so keep them for eligibility and render the resulting ESC edge.
            for ca, principals in published_enrollers(template, include_common=True):
                ca_fps = adcs_cert_fingerprints([ca], "ca")
                if not ca_fps or not ntauth.intersection(ca_fps):
                    continue
                eligible_cas.append((ca, principals))
            if not eligible_cas:
                continue
            template_id = template_ids[id(template)]
            template_node = nodes_by_id[template_id]
            enrollers = sorted({principal for _, principals in eligible_cas for principal in principals})
            if not enrollers:
                continue
            ca_names = sorted({adcs_name(ca) for ca, _ in eligible_cas})
            template_dn = scalar(attr(template, "distinguishedName"))
            finding_id = f"adcs-finding::ESC13::{hashlib.sha1(template_dn.casefold().encode()).hexdigest()[:12]}"
            if finding_id not in nodes_by_id:
                finding_node = {
                    "id": finding_id, "name": f"ESC13 · {adcs_name(template)}",
                    "type": "adcs_finding", "dn": template_dn, "sid": "", "owner": "",
                    "control": "", "memberOf": [], "esc": "ESC13",
                    "templateName": adcs_name(template), "templateDN": template_dn,
                    "esc13Policies": [],
                }
                nodes.append(finding_node)
                nodes_by_id[finding_id] = finding_node
            finding_policies = nodes_by_id[finding_id].setdefault("esc13Policies", [])
            finding_policy = {"oid": policy_oid, "policyName": adcs_name(oid),
                              "groupName": group_node["name"], "groupDN": group_dn}
            if finding_policy not in finding_policies:
                finding_policies.append(finding_policy)
            group_edge_id = f"oid-group-link::{finding_id}::{group_id}"
            if group_edge_id not in relation_ids:
                relation_ids.add(group_edge_id)
                edges.append({
                    "id": group_edge_id, "kind": "oid_group_link",
                    "source": finding_id, "target": group_id,
                    "sourceName": nodes_by_id[finding_id]["name"], "sourceType": "adcs_finding",
                    "targetName": group_node["name"], "targetType": group_node["type"],
                    "objectType": "msDS-OIDToGroupLink", "issuancePolicyOID": policy_oid,
                    "linkedGroupDN": group_dn,
                    "traversable": True,
                })

            # Annotate the existing enrollment ACL edge instead of rendering a
            # separate Enroll label: for this template the permission is the
            # first step of the ESC13 chain the user is inspecting.
            enrollment_evidence = [
                f"The principal can enroll on {adcs_name(template)}, published on {', '.join(ca_names)}.",
                f"The template references issuance policy {policy_oid}, linked to group {group_dn}.",
                "The publishing CA certificate matches an NTAuth certificate.",
                "A certificate issued under this policy can add the linked group SID to the Kerberos PAC; effective impact depends on that group's privileges.",
            ]
            for trustee in enrollers:
                source_id = principal_node(trustee)
                source_node = nodes_by_id[source_id]
                matching = [edge for edge in edges
                            if (edge.get("kind") == "dacl" or
                                (edge.get("kind") == "adcs_esc" and edge.get("adcsEsc13")
                                 and scalar(edge.get("templateDN")).casefold() == template_dn.casefold()))
                            and edge.get("source") == source_id
                            and (edge.get("target") == template_id or edge.get("target") == finding_id)
                            and "CERTIFICATE-ENROLLMENT" in scalar(edge.get("objectType")).upper()]
                for edge in matching:
                    edge["originalRights"] = edge.get("right", "")
                    edge["target"] = finding_id
                    edge["targetName"] = nodes_by_id[finding_id]["name"]
                    edge["targetType"] = "adcs_finding"
                    policy_links = edge.setdefault("esc13Policies", [])
                    link = {"oid": policy_oid, "policyName": adcs_name(oid),
                            "groupDN": group_dn, "groupName": group_node["name"]}
                    if link not in policy_links:
                        policy_links.append(link)
                    edge.update({
                        "kind": "adcs_esc", "esc": "ESC13", "adcsEsc13": True,
                        "templateName": adcs_name(template),
                        "objectLabel": "Certificate Template", "templateDN": scalar(attr(template, "distinguishedName")),
                        "issuancePolicyOID": ", ".join(item["oid"] for item in policy_links),
                        "issuancePolicyName": ", ".join(item["policyName"] for item in policy_links),
                        "linkedGroupDN": ", ".join(item["groupDN"] for item in policy_links),
                        "linkedGroupName": ", ".join(item["groupName"] for item in policy_links),
                        "caName": ", ".join(ca_names),
                        "enrollers": enrollers, "isACL": False, "traversable": True,
                        "evidence": list(dict.fromkeys((edge.get("evidence") or []) + enrollment_evidence)),
                    })
                if not matching:
                    edge_id = f"adcs::ESC13::{source_id}::{finding_id}"
                    if edge_id not in relation_ids:
                        relation_ids.add(edge_id)
                        edges.append({
                            "id": edge_id, "kind": "adcs_esc", "esc": "ESC13",
                            "adcsEsc13": True, "source": source_id, "target": finding_id,
                            "sourceName": source_node["name"], "sourceType": source_node["type"],
                            "targetName": nodes_by_id[finding_id]["name"], "targetType": "adcs_finding",
                            "right": "ADCSESC13", "originalRights": "ENROLL",
                            "objectType": "Certificate-Enrollment", "templateName": adcs_name(template),
                            "objectLabel": "Certificate Template", "templateDN": template_dn,
                            "issuancePolicyOID": policy_oid, "issuancePolicyName": adcs_name(oid),
                            "linkedGroupDN": group_dn, "linkedGroupName": group_node["name"],
                            "caName": ", ".join(ca_names), "enrollers": enrollers,
                            "isACL": False, "traversable": True, "evidence": enrollment_evidence,
                        })

    for item in entries:
        mappings = attr(item, "altSecurityIdentities")
        if not mappings:
            continue
        identity = scalar(attr(item, "sAMAccountName")) or adcs_name(item)
        account_item = dict(item)
        account_item["__daclgraph_adcs_kind"] = "account"
        emit_indicator("ESC14", account_item, identity,
                       ["The account has an altSecurityIdentities mapping.",
                        "Whether the mapping is weak depends on certificate mapping rules and the mapping value; neither was fully assessed."])


def build_dataset(entries: list[dict[str, Any]], domain: str, selected: set[str]) -> dict[str, Any]:
    nodes, edges = [], []
    by_name: dict[str, str] = {}
    entries_by_node_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        kind = classify(entry)
        if kind not in selected:
            continue
        descriptor = entry.get("nTSecurityDescriptor") or {}
        # bloodyAD serializes single-valued LDAP attributes as one-item arrays.
        if isinstance(descriptor, list):
            descriptor = descriptor[0] if descriptor else {}
        if not isinstance(descriptor, dict):
            descriptor = {}
        dn = scalar(entry.get("distinguishedName"))
        sam = scalar(entry.get("sAMAccountName"))
        display_name = scalar(entry.get("displayName"))
        rdn = dn.split(",", 1)[0] if dn else ""
        rdn = re.sub(r"^(?:CN|OU)=", "", rdn, flags=re.IGNORECASE)
        name = sam or display_name or scalar(entry.get("name")) or scalar(entry.get("cn")) or rdn or "(unnamed)"
        node_id = stable_id(entry)
        if not node_id:
            continue
        entries_by_node_id[node_id] = entry
        uac = attr(entry, "userAccountControl", []) or []
        uac_present = attr(entry, "userAccountControl") is not None
        if isinstance(uac, str):
            uac = [uac]
        sid_history = attr(entry, "sIDHistory", []) or []
        if not isinstance(sid_history, list):
            sid_history = [sid_history]
        uac_flags = {
            part.strip().upper()
            for flag in uac
            for part in re.split(r"[;|,]", scalar(flag))
            if part.strip()
        }
        delegate_to = attr(entry, "msDS-AllowedToDelegateTo", []) or []
        if isinstance(delegate_to, str):
            delegate_to = [delegate_to]
        service_principal_names = attr(entry, "servicePrincipalName", []) or []
        if isinstance(service_principal_names, str):
            service_principal_names = [service_principal_names]
        service_principal_names = [scalar(value).strip() for value in service_principal_names
                                   if scalar(value).strip()]
        admin_count = scalar(attr(entry, "adminCount")).strip().casefold() in {"1", "true"}
        no_preauth = bool({"DONT_REQ_PREAUTH", "DONT_REQUIRE_PREAUTH"} & uac_flags)
        members = entry.get("member", [])
        if kind == "group" and (sam or name).casefold() in {"domain users", "enterprise admins"}:
            members = []
        nodes.append({"id": node_id, "name": name, "type": kind, "dn": dn,
                      "sid": scalar(entry.get("objectSid")), "owner": scalar(descriptor.get("Owner")),
                      "sidHistory": [sid for value in sid_history
                                     for sid in [canonical_sid(value)] if sid],
                      "control": scalar(descriptor.get("Control")),
                      "memberOf": entry.get("memberOf", []), "members": members,
                      "dNSHostName": scalar(attr(entry, "dNSHostName")),
                      "primaryGroupID": scalar(entry.get("primaryGroupID")),
                      "samAccountName": sam, "displayName": display_name,
                      "description": scalar(attr(entry, "description")),
                      "gPLink": scalar(entry.get("gPLink")),
                      "gPOptions": scalar(entry.get("gPOptions")),
                      "gPCFileSysPath": scalar(entry.get("gPCFileSysPath")),
                      "gPCWQLFilter": scalar(entry.get("gPCWQLFilter")),
                      "versionNumber": scalar(entry.get("versionNumber")),
                      "userAccountControl": sorted(uac_flags),
                      "adminCount": admin_count,
                      "servicePrincipalNames": service_principal_names,
                      "asrepRoastable": kind == "user" and no_preauth and "ACCOUNTDISABLE" not in uac_flags,
                      "kerberoastable": kind == "user" and bool(service_principal_names) and "ACCOUNTDISABLE" not in uac_flags,
                      "enabled": ("ACCOUNTDISABLE" not in uac_flags) if uac_present and kind in {"user", "computer"} else None,
                      "unconstrainedDelegation": "TRUSTED_FOR_DELEGATION" in uac_flags,
                      "protocolTransition": "TRUSTED_TO_AUTH_FOR_DELEGATION" in uac_flags,
                      "allowedToDelegateTo": [scalar(spn) for spn in delegate_to if scalar(spn)]})
        owner = scalar(descriptor.get("Owner")).strip()
        if owner:
            edges.append({"id": f"owner::{node_id}::{owner.casefold()}", "kind": "ownership",
                          "source": owner, "target": node_id, "sourceName": owner,
                          "targetName": name, "targetType": kind, "right": "OWNERSHIP",
                          "objectType": "Owner", "type": "OWNER", "inherited": False,
                          "isACL": False})
        for ace_index, ace in enumerate(descriptor.get("ACL", []) or []):
            if not isinstance(ace, dict):
                continue
            for trustee in trustees(ace.get("Trustee")):
                for object_index, object_type in enumerate(object_types(ace.get("ObjectType"))):
                    edge_id = f"{node_id}::{ace_index}::{trustee}::{object_index}"
                    edges.append({"id": edge_id, "kind": "dacl", "source": trustee, "target": node_id,
                                  "sourceName": trustee, "targetName": name,
                                  "targetType": kind, "aceIndex": ace_index,
                                  "type": scalar(ace.get("Type")), "right": scalar(ace.get("Right")),
                                  "objectType": object_type,
                                  "inheritedObjectType": scalar(ace.get("InheritedObjectType")),
                                  "flags": scalar(ace.get("Flags")),
                                  "inherited": "INHERITED" in scalar(ace.get("Flags")).upper(),
                                  "raw": ace})
        # A gMSA password reader list is stored in its own security descriptor,
        # separate from nTSecurityDescriptor. Both READ_PROP and CONTROL_ACCESS
        # are required to retrieve msDS-ManagedPassword (GENERIC_ALL includes both).
        gmsa_sd = attr(entry, "msDS-GroupMSAMembership") or {}
        if isinstance(gmsa_sd, list):
            gmsa_sd = gmsa_sd[0] if gmsa_sd else {}
        object_classes = entry.get("objectClass") or []
        if isinstance(object_classes, str):
            object_classes = [object_classes]
        if isinstance(gmsa_sd, dict) and "msds-groupmanagedserviceaccount" in {
            scalar(value).casefold() for value in object_classes
        }:
            for gmsa_ace_index, ace in enumerate(gmsa_sd.get("ACL", []) or []):
                if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                    continue
                rights = {part.strip().upper() for part in scalar(ace.get("Right")).split("|")}
                can_read_gmsa = "GENERIC_ALL" in rights or (
                    "READ_PROP" in rights and "CONTROL_ACCESS" in rights
                )
                if not can_read_gmsa:
                    continue
                for trustee in trustees(ace.get("Trustee")):
                    edges.append({"id": f"gmsa-read::{node_id}::{gmsa_ace_index}::{trustee.casefold()}",
                                  "kind": "dacl", "source": trustee, "target": node_id,
                                  "sourceName": trustee, "targetName": name,
                                  "targetType": kind, "aceIndex": gmsa_ace_index,
                                  "type": scalar(ace.get("Type")), "right": scalar(ace.get("Right")),
                                  "objectType": "msDS-ManagedPassword",
                                  "descriptorAttribute": "msDS-GroupMSAMembership",
                                  "gmsaPasswordRead": True,
                                  "flags": scalar(ace.get("Flags")),
                                  "inherited": "INHERITED" in scalar(ace.get("Flags")).upper(),
                                  "raw": ace})
    object_ids: dict[str, str] = {}
    for node in nodes:
        object_ids[node["name"].casefold()] = node["id"]
        if node["dn"]:
            object_ids[node["dn"].casefold()] = node["id"]
            object_ids[node["dn"].split(",", 1)[0].removeprefix("CN=").casefold()] = node["id"]
        if node["sid"]:
            object_ids[node["sid"].casefold()] = node["id"]
    # Resolve SPNs to their computer by exact SPN or hostname. AD commonly
    # stores many service SPNs on one computer, so they must share one edge.
    spn_owner: dict[str, str] = {}
    host_owner: dict[str, str] = {}
    for node in nodes:
        entry = entries_by_node_id.get(node["id"], {})
        spns = attr(entry, "servicePrincipalName", []) or []
        if isinstance(spns, str):
            spns = [spns]
        for spn in spns:
            value = scalar(spn).strip()
            if value:
                spn_owner[value.casefold()] = node["id"]
        if node["type"] == "computer":
            hosts = [node.get("dNSHostName", ""), node.get("samAccountName", "").removesuffix("$")]
            for host in hosts:
                normalized_host = scalar(host).strip().rstrip(".").casefold()
                if normalized_host:
                    host_owner[normalized_host] = node["id"]
                    host_owner.setdefault(normalized_host.split(".", 1)[0], node["id"])
    for edge in edges:
        trustee = edge["source"]
        normalized_trustee = trustee.casefold().split("\\")[-1]
        source_id = object_ids.get(trustee.casefold()) or object_ids.get(normalized_trustee)
        if not source_id and normalized_trustee.endswith("$"):
            source_id = object_ids.get(normalized_trustee[:-1])
        edge["source"] = source_id or f"trustee::{trustee.casefold()}"
        if edge["source"].startswith("trustee::"):
            by_name[edge["source"]] = trustee
        else:
            source_node = next((node for node in nodes if node["id"] == edge["source"]), None)
            if source_node:
                edge["sourceName"] = source_node["name"]
                edge["sourceType"] = source_node["type"]
    for node_id, trustee in by_name.items():
        nodes.append({"id": node_id, "name": trustee, "type": "trustee", "dn": "", "sid": "",
                      "owner": "", "control": "", "memberOf": []})
    node_by_id = {node["id"]: node for node in nodes}
    service_ids: dict[str, str] = {}
    # Group constrained-delegation SPNs by account and target. Keep the graph
    # readable while preserving every SPN on the relationship for its details.
    for principal in list(nodes):
        delegated_targets: dict[str, dict[str, Any]] = {}
        for spn in principal.get("allowedToDelegateTo", []):
            key = spn.casefold()
            service_id = spn_owner.get(key)
            parts = spn.split("/", 1)
            host = parts[1].split("/", 1)[0].split(":", 1)[0].rstrip(".").casefold() if len(parts) == 2 else ""
            if not service_id and host:
                service_id = host_owner.get(host) or host_owner.get(host.split(".", 1)[0])
            if not service_id:
                service_key = host or key
                service_id = service_ids.get(service_key)
                if not service_id:
                    service_id = f"service::{service_key}"
                    service_ids[service_key] = service_id
                    nodes.append({"id": service_id, "name": host or spn, "type": "service", "dn": "",
                                  "sid": "", "owner": "", "control": "", "memberOf": [],
                                  "servicePrincipalName": spn})
                    node_by_id[service_id] = nodes[-1]
            target = delegated_targets.setdefault(service_id, {"spns": []})
            if spn not in target["spns"]:
                target["spns"].append(spn)
        for service_id, delegated in delegated_targets.items():
            target_node = node_by_id.get(service_id)
            edges.append({"id": f"delegation::constrained::{principal['id']}::{service_id}",
                          "kind": "delegation", "delegationType": "constrained",
                          "source": principal["id"], "target": service_id,
                          "sourceName": principal["name"], "sourceType": principal["type"],
                          "targetName": target_node["name"] if target_node else service_id,
                          "targetType": target_node["type"] if target_node else "service",
                          "right": "AllowedToDelegate", "objectType": delegated["spns"][0],
                          "serviceSPNs": delegated["spns"],
                          "protocolTransition": principal.get("protocolTransition", False),
                          "isACL": False, "inherited": False})
    # Resource-based constrained delegation descriptor: allowed principal -> resource.
    for entry in entries:
        target_id = object_ids.get(scalar(attr(entry, "distinguishedName")).casefold())
        if not target_id:
            continue
        rbcd = attr(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity") or {}
        if isinstance(rbcd, list):
            rbcd = rbcd[0] if rbcd else {}
        if not isinstance(rbcd, dict):
            continue
        for ace_index, ace in enumerate(rbcd.get("ACL", []) or []):
            if not isinstance(ace, dict) or "DENIED" in scalar(ace.get("Type")).upper():
                continue
            target_node = node_by_id.get(target_id)
            for principal_name in trustees(ace.get("Trustee")):
                principal_id = object_ids.get(principal_name.casefold())
                if not principal_id:
                    principal_id = f"trustee::{principal_name.casefold()}"
                    if principal_id not in node_by_id:
                        nodes.append({"id": principal_id, "name": principal_name, "type": "trustee",
                                      "dn": "", "sid": "", "owner": "", "control": "", "memberOf": []})
                        node_by_id[principal_id] = nodes[-1]
                principal_node = node_by_id.get(principal_id)
                edges.append({"id": f"delegation::rbcd::{target_id}::{ace_index}::{principal_name.casefold()}",
                              "kind": "delegation", "delegationType": "rbcd",
                              "source": principal_id, "target": target_id,
                              "sourceName": principal_node["name"] if principal_node else principal_name,
                              "sourceType": principal_node["type"] if principal_node else "trustee",
                              "targetName": target_node["name"] if target_node else target_id,
                              "targetType": target_node["type"] if target_node else "object",
                              "right": "AllowedToAct", "objectType": "msDS-AllowedToActOnBehalfOfOtherIdentity",
                              "type": scalar(ace.get("Type")), "flags": scalar(ace.get("Flags")),
                              "inherited": "INHERITED" in scalar(ace.get("Flags")).upper(),
                              "raw": ace, "isACL": False})
    # sIDHistory is stored on the source principal and names the historical
    # principal whose SID its Kerberos token can carry. Resolve exact collected SIDs.
    for principal in list(nodes):
        for historic_sid in principal.get("sidHistory", []):
            historical_id = object_ids.get(historic_sid.casefold())
            historical = node_by_id.get(historical_id)
            if historical and historical.get("type") in {"user", "group", "computer"}:
                edges.append({"id": f"sid-history::{principal['id']}::{historical_id}",
                              "kind": "sid_history", "source": principal["id"],
                              "target": historical_id, "sourceName": principal["name"],
                              "sourceType": principal["type"], "targetName": historical["name"],
                              "targetType": historical["type"], "right": "SID_HISTORY",
                              "objectType": historic_sid, "isACL": False, "inherited": False})

    # Add direct membership edges from memberOf, group.member, and primaryGroupID.
    # These are kept direct so nested group paths remain explicit and traversable.
    node_by_id = {node["id"]: node for node in nodes}
    membership_pairs: set[tuple[str, str]] = set()

    def add_membership(member_id: str, group_id: str) -> None:
        if member_id == group_id or (member_id, group_id) in membership_pairs:
            return
        member, group = node_by_id.get(member_id), node_by_id.get(group_id)
        if not member or not group or group.get("type") != "group":
            return
        group_name = (scalar(group.get("samAccountName")) or scalar(group.get("name"))).casefold()
        if group_name in {"domain users", "enterprise admins"}:
            return
        membership_pairs.add((member_id, group_id))
        edges.append({"id": f"member::{member_id}::{group_id}", "kind": "membership",
                      "source": member_id, "target": group_id,
                      "sourceName": member["name"], "sourceType": member["type"],
                      "targetName": group["name"], "targetType": "group",
                      "right": "MEMBER_OF", "objectType": "MemberOf",
                      "type": "MEMBERSHIP", "flags": "", "inherited": False})

    for node in list(nodes):
        memberships = node.get("memberOf") or []
        if isinstance(memberships, str):
            memberships = [memberships]
        for group_dn in memberships:
            if not isinstance(group_dn, str):
                continue
            group_id = object_ids.get(group_dn.casefold())
            group = node_by_id.get(group_id)
            if group_id:
                add_membership(node["id"], group_id)
        members = node.get("members") or []
        if isinstance(members, str):
            members = [members]
        for member_dn in members:
            if isinstance(member_dn, str):
                member_id = object_ids.get(member_dn.casefold())
                if member_id:
                    add_membership(member_id, node["id"])
        if node.get("type") in {"user", "computer"} and node.get("primaryGroupID"):
            sid = node.get("sid", "")
            if sid.count("-") >= 4:
                group_id = object_ids.get(f"{sid.rsplit('-', 1)[0]}-{node['primaryGroupID']}".casefold())
                if group_id:
                    add_membership(node["id"], group_id)

    # A scope object links GPOs through its gPLink attribute. Keep this distinct
    # from DACL edges so the viewer can label and style scope relationships.
    for scope in list(nodes):
        if scope.get("type") not in {"ou", "domain"} and not scope.get("gPLink"):
            continue
        for order, match in enumerate(re.finditer(r"\[LDAP://(.+?);(\d+)\]", scope.get("gPLink", ""), re.IGNORECASE), 1):
            gpo_dn, options_text = match.groups()
            gpo_id = object_ids.get(gpo_dn.strip().casefold())
            gpo = node_by_id.get(gpo_id)
            if not gpo or gpo.get("type") != "gpo":
                continue
            options = int(options_text)
            edges.append({"id": f"gpolink::{scope['id']}::{gpo_id}::{order}",
                          "kind": "gpo_link", "source": scope["id"], "target": gpo_id,
                          "sourceName": scope["name"], "sourceType": scope["type"],
                          "targetName": gpo["name"], "targetType": "gpo",
                          "right": "GP_LINK", "objectType": "gPLink", "type": "GPO_LINK",
                          "linkOrder": order, "linkOptions": options,
                          "linkEnabled": not bool(options & 1), "enforced": bool(options & 2),
                          "flags": f"order={order}; enabled={not bool(options & 1)}; enforced={bool(options & 2)}",
                          "inherited": False})
    if any(entry.get("__daclgraph_adcs_kind") for entry in entries):
        add_adcs_findings(entries, nodes, edges, object_ids, domain)
    adcs_entries_present = any(entry.get("__daclgraph_adcs_kind") for entry in entries)
    adcs_report = adcs_assessment(entries, edges) if adcs_entries_present else []
    return {"schema": "daclgraph/v1", "domain": domain,
            "collectedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "filters": {"types": sorted(selected)}, "nodes": nodes, "edges": edges,
            "adcsAssessment": adcs_report,
            "stats": {"objects": len([n for n in nodes if n["type"] not in {"trustee", "adcs_finding"}]),
                      "trustees": len([n for n in nodes if n["type"] == "trustee"]),
            "aces": len({(e["target"], e.get("descriptorAttribute", "nTSecurityDescriptor"), e["aceIndex"])
                         for e in edges if e.get("kind") == "dacl" or "aceIndex" in e}),
                      "adcsFindings": len({(e.get("esc", "ESC13" if e.get("adcsEsc13") else ""), e.get("templateDN", ""))
                                           for e in edges if e.get("kind") == "adcs_esc" or e.get("adcsEsc13")}),
                      "adcsCandidates": sum(item["status"] == "candidate" for item in adcs_report),
                      "adcsRemoteChecks": sum(item["status"] == "requires_remote_check" for item in adcs_report)}}


def _graph_pid_file(bind: str, port: int) -> Path:
    safe_bind = re.sub(r"[^A-Za-z0-9_.-]+", "_", bind)
    runtime_base = os.environ.get("XDG_RUNTIME_DIR") or str(Path.home() / ".local" / "state")
    runtime = Path(runtime_base).expanduser() / "daclhound"
    return runtime / f"graph-{safe_bind}-{port}.pid"


def _graph_daemon_matches(pid: int) -> bool:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        return False
    return (str(Path(__file__).resolve()).encode() in command
            and b"graph" in command and b"--_daemon-child" in command)


def _read_graph_pid(path: Path) -> int | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        pid = int(value["pid"])
        return pid if pid > 1 else None
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _start_graph_server(bind: str, port: int, input_path: str | None, verbose: bool) -> int:
    pid_file = _graph_pid_file(bind, port)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    previous_pid = _read_graph_pid(pid_file)
    if previous_pid and _graph_daemon_matches(previous_pid):
        print(f"[+] DACLhound graph already running at http://{bind}:{port}/ (PID {previous_pid})")
        return 0
    pid_file.unlink(missing_ok=True)
    command = [sys.executable, str(Path(__file__).resolve()), "graph", "run",
               "--bind", bind, "--port", str(port), "--_daemon-child",
               "--_pid-file", str(pid_file)]
    if input_path:
        command.extend(["--input", input_path])
    if verbose:
        command.append("--verbose")
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    deadline = time.monotonic() + 5.0
    ready = False
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            with socket.create_connection((bind, port), timeout=0.15):
                ready = True
                break
        except OSError:
            time.sleep(0.1)
    if not ready:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
        raise RuntimeError(f"Could not start the graph server on {bind}:{port}; check whether the port is already in use")
    pid_file.write_text(json.dumps({"pid": process.pid, "bind": bind, "port": port}) + "\n", encoding="utf-8")
    print(f"[+] DACLhound graph started at http://{bind}:{port}/ (PID {process.pid})")
    print("[+] Stop it with: DACLhound.py graph stop")
    return 0


def _stop_graph_server(bind: str, port: int) -> int:
    pid_file = _graph_pid_file(bind, port)
    pid = _read_graph_pid(pid_file)
    if not pid or not _graph_daemon_matches(pid):
        pid_file.unlink(missing_ok=True)
        print(f"[i] No DACLhound background server found for {bind}:{port}")
        return 0
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not _graph_daemon_matches(pid):
            pid_file.unlink(missing_ok=True)
            print(f"[+] DACLhound graph stopped (PID {pid})")
            return 0
        time.sleep(0.1)
    raise RuntimeError(f"DACLhound graph PID {pid} did not stop within 5 seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect Active Directory DACLs or serve an interactive graph.")
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
    collection.add_argument("--types", default="users,groups,computers,ous,containers,gpos,domain",
                            help="Comma-separated object types: users, groups, computers, OUs, containers, GPOs, domain")
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
    ns = parser.parse_args()

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
                "domain": ("domain", "(objectClass=domainDNS)")}
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
             "servicePrincipalName,dNSHostName,adminCount")
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


if __name__ == "__main__":
    raise SystemExit(entrypoint())
