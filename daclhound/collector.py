"""bloodyAD authentication, LDAP collection, and normalized graph construction."""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any

from .adcs import adcs_assessment, add_adcs_findings
from .common import (attr, canonical_sid, classify, int_attr, object_types, scalar,
                     stable_id, trustee_display_name, trustees)


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


def request_tgt_ccache_hex(username: str, domain: str, password: str, kdc_host: str) -> str:
    """Request a TGT with Impacket and return its ccache as hex for bloodyAD.

    Impacket first asks the KDC for its pre-authentication salt. This supports
    accounts whose AES salt differs from kerbad's default realm+username salt.
    The ccache stays in memory and is passed to bloodyAD's Python API.
    """
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal

    principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, _cipher, old_session_key, session_key = getKerberosTGT(
        clientName=principal,
        password=password,
        domain=domain.upper(),
        lmhash=b"",
        nthash=b"",
        aesKey=None,
        kdcHost=kdc_host,
    )
    ccache = CCache()
    ccache.fromTGT(tgt, old_session_key, session_key)
    return ccache.getData().hex()


def request_tgt_ccache_data(username: str, domain: str, kdc_host: str,
                            password: str | None = None, nt_hash: str | None = None,
                            aes_key: str | None = None) -> bytes:
    """Acquire a TGT in-process and return a ccache byte string without writing it to disk."""
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal

    principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, _cipher, old_session_key, session_key = getKerberosTGT(
        clientName=principal,
        password=password or "",
        domain=domain.upper(),
        lmhash=b"",
        nthash=bytes.fromhex(nt_hash) if nt_hash else b"",
        aesKey=bytes.fromhex(aes_key) if aes_key else None,
        kdcHost=kdc_host,
    )
    ccache = CCache()
    ccache.fromTGT(tgt, old_session_key, session_key)
    return ccache.getData()


def kerberos_kdc_for_user_realm(domain: str, target_host: str, target_dc_ip: str | None) -> str:
    """Find a KDC in the credential realm, which may differ from the LDAP DC."""
    realm = domain.rstrip(".").lower()
    target = target_host.rstrip(".").lower()
    if target == realm or target.endswith("." + realm):
        return target_dc_ip or target_host

    source_fqdn = os.environ.get("FQDN", "").rstrip(".")
    if source_fqdn and (source_fqdn.lower() == realm or source_fqdn.lower().endswith("." + realm)):
        return os.environ.get("DC_IP") or source_fqdn

    try:
        import dns.resolver
        for query in (f"_kerberos._tcp.dc._msdcs.{domain}", f"_kerberos._tcp.{domain}"):
            try:
                records = dns.resolver.resolve(query, "SRV")
            except Exception:
                continue
            ordered = sorted(records, key=lambda item: (item.priority, -item.weight, str(item.target)))
            if ordered:
                return str(ordered[0].target).rstrip(".")
    except ImportError:
        pass

    try:
        import socket
        socket.gethostbyname(domain)
        return domain
    except OSError as exc:
        raise RuntimeError(
            f"Could not locate a KDC for credential realm {domain} while targeting {target_host}. "
            "Set FQDN and DC_IP to a DC in the credential realm, or use an existing ccache with -k."
        ) from exc


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

    memory_ccache_hex = None
    if kerberos and password and not kerberos_ticket and not auth_format:
        credential_kdc = kerberos_kdc_for_user_realm(domain, host, dc_ip)
        memory_ccache_hex = request_tgt_ccache_hex(username or "", domain, password, credential_kdc)

    krb_args = ([f"ccache={memory_ccache_hex}"] if memory_ccache_hex else
                [f"ccache={kerberos_ticket}"] if kerberos_ticket else []) if kerberos else None
    config = Config(host=host, domain=domain, username=username or "",
                    password="" if memory_ccache_hex else (password or ""),
                    krb_args=krb_args, dcip=dc_ip or "", timeout=timeout,
                    scheme="ldaps" if secure else "ldap",
                    format="hex" if memory_ccache_hex else auth_format)
    conn = ConnectionHandler(config=config)
    entries: list[dict[str, Any]] = []
    try:
        for kind in sorted(requested):
            _, ldap_filter = type_map[kind]
            base = "DOMAIN"
            if kind == "sites":
                ldap = await conn.getLdap()
                base = f"CN=Sites,{ldap.configNC}"
            label = "domain trusts" if kind == "trusts" else f"{kind} DACLs"
            print(f"[*] Collecting {label} from {host}", file=sys.stderr)
            try:
                async for entry in bloodyad_search(conn, base=base, filter=ldap_filter,
                                                   attr=attrs, resolve_sd=True):
                    entries.append(json_value(entry))
            except NoResultError as exc:
                optional_types = {"trusts", "sites", "foreign-security-principals"}
                if kind in optional_types and exc.filter == ldap_filter:
                    print(f"[i] No {kind.replace('-', ' ')} found; continuing", file=sys.stderr)
                    continue
                raise
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
        if kind == "trusted_domain":
            name = scalar(attr(entry, "trustPartner")) or name
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
                      "allowedToDelegateTo": [scalar(spn) for spn in delegate_to if scalar(spn)],
                      "trustPartner": scalar(attr(entry, "trustPartner")),
                      "trustDirection": scalar(attr(entry, "trustDirection")),
                      "trustType": scalar(attr(entry, "trustType")),
                      "trustAttributes": scalar(attr(entry, "trustAttributes")),
                      "securityIdentifier": scalar(attr(entry, "securityIdentifier")),
                      "remoteDomainSid": canonical_sid(attr(entry, "securityIdentifier"))})
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
    host_owners: dict[str, set[str]] = {}
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
                    host_owners.setdefault(normalized_host, set()).add(node["id"])
                    host_owners.setdefault(normalized_host.split(".", 1)[0], set()).add(node["id"])
    for edge in edges:
        trustee = edge["source"]
        normalized_trustee = trustee.casefold().split("\\")[-1]
        source_id = object_ids.get(trustee.casefold()) or object_ids.get(normalized_trustee)
        if not source_id and normalized_trustee.endswith("$"):
            source_id = object_ids.get(normalized_trustee[:-1])
        edge["source"] = source_id or f"trustee::{trustee.casefold()}"
        if edge["source"].startswith("trustee::"):
            display_name = trustee_display_name(trustee)
            edge["sourceName"] = display_name
            by_name[edge["source"]] = display_name
        else:
            source_node = next((node for node in nodes if node["id"] == edge["source"]), None)
            if source_node:
                edge["sourceName"] = source_node["name"]
                edge["sourceType"] = source_node["type"]
    for node_id, trustee_name in by_name.items():
        sid = canonical_sid(node_id.removeprefix("trustee::"))
        nodes.append({"id": node_id, "name": trustee_name, "type": "trustee", "dn": "", "sid": sid,
                      "owner": "", "control": "", "memberOf": []})
    node_by_id = {node["id"]: node for node in nodes}
    domain_nodes = [node for node in nodes if node["type"] == "domain"]
    local_domain = next((node for node in domain_nodes
                         if scalar(node.get("name")).casefold() == domain.casefold()),
                        domain_nodes[0] if domain_nodes else None)
    if local_domain:
        for trust_node in (node for node in nodes if node["type"] == "trusted_domain"):
            partner = scalar(trust_node.get("trustPartner")) or trust_node["name"]
            edges.append({"id": f"domain-trust::{local_domain['id']}::{trust_node['id']}",
                          "kind": "domain_trust", "source": local_domain["id"],
                          "target": trust_node["id"], "sourceName": local_domain["name"],
                          "sourceType": "domain", "targetName": partner,
                          "targetType": "trusted_domain", "right": "TRUSTED_DOMAIN",
                          "trustDirection": trust_node.get("trustDirection", ""),
                          "trustType": trust_node.get("trustType", ""),
                          "trustAttributes": trust_node.get("trustAttributes", ""),
                          "isACL": False, "inherited": False})
    # Mirror RustHound-CE's SPN-derived SQLAdmin display for user service
    # accounts. A computer account's own MSSQLSvc SPN does not make that host
    # an SQL administrator. SQL Server roles are not queried or verified.
    sql_targets: dict[tuple[str, str], dict[str, Any]] = {}
    for principal in nodes:
        if principal["type"] != "user":
            continue
        entry = entries_by_node_id.get(principal["id"], {})
        spns = attr(entry, "servicePrincipalName", []) or []
        if isinstance(spns, str):
            spns = [spns]
        for raw_spn in spns:
            spn = scalar(raw_spn).strip()
            parts = spn.split("/", 1)
            if len(parts) != 2 or parts[0].casefold() != "mssqlsvc":
                continue
            # MSSQLSvc SPNs commonly use host:port or host:instance.
            endpoint = parts[1].split("/", 1)[0].strip().rstrip(".")
            host, _, port_or_instance = endpoint.partition(":")
            host_key = host.casefold().rstrip(".")
            if not host_key:
                continue
            candidates = host_owners.get(host_key, set())
            target_id = next(iter(candidates)) if len(candidates) == 1 else None
            if target_id is None:
                # Preserve the LDAP evidence when no unique Computer object
                # can be resolved, rather than linking to the wrong forest.
                target_id = f"sqlservice::{host_key}"
                if target_id not in node_by_id:
                    service_node = {"id": target_id, "name": host, "type": "service", "dn": "",
                                    "sid": "", "owner": "", "control": "", "memberOf": [],
                                    "servicePrincipalName": spn}
                    nodes.append(service_node)
                    node_by_id[target_id] = service_node
            key = (principal["id"], target_id)
            item = sql_targets.setdefault(key, {"spns": [], "endpoints": []})
            if spn not in item["spns"]:
                item["spns"].append(spn)
            port_value = port_or_instance or "1433"
            endpoint_detail = {"host": host, "portOrInstance": port_value, "spn": spn}
            if endpoint_detail not in item["endpoints"]:
                item["endpoints"].append(endpoint_detail)
    for (principal_id, target_id), details in sql_targets.items():
        principal, target_node = node_by_id[principal_id], node_by_id[target_id]
        edges.append({"id": f"sql-admin::{principal_id}::{target_id}", "kind": "sql_admin",
                      "source": principal_id, "target": target_id,
                      "sourceName": principal["name"], "sourceType": principal["type"],
                      "targetName": target_node["name"], "targetType": target_node["type"],
                      "right": "SQLAdmin", "objectType": "MSSQLSvc",
                      "serviceSPNs": details["spns"], "sqlEndpoints": details["endpoints"],
                      "isACL": False, "inherited": False})
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
                        nodes.append({"id": principal_id, "name": trustee_display_name(principal_name), "type": "trustee",
                                      "dn": "", "sid": canonical_sid(principal_name), "owner": "", "control": "", "memberOf": []})
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
