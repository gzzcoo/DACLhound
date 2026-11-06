"""Native LDAP collection and analysis for AD CS relationships and ESC findings."""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from .common import attr, canonical_sid, int_attr, object_types, scalar, trustees

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


_CERTIFICATE_ENROLLMENT_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"


def _is_certificate_enrollment_ace(ace: dict[str, Any]) -> bool:
    """Recognize the enrollment extended right by GUID or its display name."""
    raw = ace.get("raw") if isinstance(ace.get("raw"), dict) else ace
    guid = scalar(raw.get("ObjectTypeGuid") or ace.get("ObjectTypeGuid")).strip("{}").casefold()
    if guid == _CERTIFICATE_ENROLLMENT_GUID:
        return True
    object_type = scalar(ace.get("ObjectType")).casefold().replace("_", "-")
    normalized = re.sub(r"[^a-z0-9]", "", object_type)
    return any(token in normalized for token in ("certificateenrollment", "enroll", "allextendedrights"))


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
        enroll_right = (
            "CONTROL_ACCESS" in rights
            and _is_certificate_enrollment_ace(ace)
        ) or (
            "WRITE_PROP" in rights and _is_certificate_enrollment_ace(ace)
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


def adcs_common_principal(value: str) -> bool:
    principals = [part.strip().casefold() for part in re.split(r"[;|]", value) if part.strip()]
    return bool(principals) and all(
        principal in COMMON_ADCS_PRINCIPALS
        or re.fullmatch(r"s-1-5-21-(?:\d+-){3}(?:498|512|513|514|515|516|517|518|519|520|521|526|527|553)", principal)
        or re.fullmatch(r"s-1-5-(?:18|19|20|32-(?:544|548|549|550|551|552|554|555|556|557|558|559|560|562|568|569|573|574|575|576|577|578|579|580|581|582|583|584|585|586|587|588|589|590|591|592|593|594|595|596|597|598|599))", principal)
        for principal in principals
    )


def adcs_cert_publishers_user_members(principal: str, edges: list[dict[str, Any]],
                                      nodes_by_id: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Return non-default users who reach Cert Publishers through group membership."""
    nodes_by_id = nodes_by_id or {}
    principal_key = principal.casefold()
    group_ids = {
        node_id for node_id, node in nodes_by_id.items()
        if scalar(node.get("type")).casefold() == "group"
        and (scalar(node.get("sid")).casefold() == principal_key
             or scalar(node.get("name")).casefold() == principal_key
             or scalar(node.get("samAccountName")).casefold() == principal_key)
    }
    if not group_ids and (principal_key == "cert publishers" or principal_key.endswith("-517")):
        group_ids = {
            scalar(edge.get("target")) for edge in edges
            if edge.get("kind") == "membership"
            and (scalar(edge.get("targetName")).casefold() == "cert publishers"
                 or scalar(edge.get("target")).casefold() == principal_key)
        }
    if not group_ids:
        return []

    members_by_group: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if edge.get("kind") == "membership":
            members_by_group.setdefault(scalar(edge.get("target")), []).append(edge)

    users: dict[str, dict[str, Any]] = {}
    pending, visited = list(group_ids), set()
    while pending:
        group_id = pending.pop()
        if group_id in visited:
            continue
        visited.add(group_id)
        for edge in members_by_group.get(group_id, []):
            member_id = scalar(edge.get("source"))
            member = nodes_by_id.get(member_id, {})
            member_type = scalar(member.get("type") or edge.get("sourceType")).casefold()
            if member_type == "group":
                pending.append(member_id)
                continue
            if member_type != "user":
                continue
            name = scalar(member.get("samAccountName") or member.get("name") or edge.get("sourceName"))
            sid = scalar(member.get("sid") or (member_id if member_id.startswith("S-1-") else ""))
            if name.casefold() in {"administrator", "guest", "krbtgt"} or sid.casefold().endswith(("-500", "-501", "-502")):
                continue
            users[member_id] = {**member, "id": member_id, "name": name, "sid": sid, "type": "user"}
    return list(users.values())


def adcs_is_cert_publishers_principal(value: str) -> bool:
    principals = [part.strip().casefold() for part in re.split(r"[;|]", value) if part.strip()]
    return any(
        principal == "cert publishers"
        or re.fullmatch(r"s-1-5-21-(?:\d+-){3}517", principal)
        for principal in principals
    )


def adcs_default_admin_principal(value: str) -> bool:
    """Exclude built-in domain admin groups from actionable ESC13 graph edges."""
    principals = [part.strip().casefold().split("\\")[-1]
                  for part in re.split(r"[;|]", value) if part.strip()]
    return bool(principals) and all(
        principal in {
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "builtin_administrators", "builtin administrators",
        }
        or re.fullmatch(r"s-1-5-21-(?:\d+-){3}(?:512|518|519)", principal)
        or principal == "s-1-5-32-544"
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
            if adcs_common_principal(trustee) and not adcs_cert_publishers_user_members(trustee, edges):
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
            if "CONTROL_ACCESS" not in rights or not _is_certificate_enrollment_ace(ace):
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

    def is_domain_controller(node: dict[str, Any]) -> bool:
        if scalar(node.get("primaryGroupID")).strip() == "516":
            return True
        flags = node.get("userAccountControl", []) or []
        if isinstance(flags, str):
            flags = re.split(r"[;|,]", flags)
        if any(scalar(flag).strip().upper() == "SERVER_TRUST_ACCOUNT" for flag in flags):
            return True
        return bool(re.search(r"(?:^|,)OU=Domain Controllers(?:,|$)",
                              scalar(node.get("dn")), re.IGNORECASE))

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
            has_enrollment = "GENERIC_ALL" in rights or (
                "CONTROL_ACCESS" in rights and _is_certificate_enrollment_ace(ace)
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
        # Default administrative groups are expected to control PKI objects.
        # Expanding their nested users turns every domain admin (for example,
        # Athena) into a misleading individual ESC5/ESC7 finding.
        if adcs_default_admin_principal(principal):
            return
        if adcs_common_principal(principal):
            if not adcs_is_cert_publishers_principal(principal):
                return
            members = adcs_cert_publishers_user_members(principal, edges, nodes_by_id)
            if members:
                for member in members:
                    member_id = scalar(member.get("id"))
                    member_name = scalar(member.get("name")) or scalar(member.get("samAccountName"))
                    member_evidence = evidence + [
                        f"{member_name} is a direct or nested user member of Cert Publishers and inherits this access."
                    ]
                    add_finding(member_id, esc, item, ca, member_id, member_name,
                                False, member_evidence, is_acl)
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
        # Treat host compromise as a separate ESC5 candidate only for a
        # dedicated CA server; a DC-hosted CA is not a useful extra graph hop.
        # ACL-derived ESC5 findings on the CA and PKI objects remain evaluated.
        if host_node and not is_domain_controller(host_node):
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
            # Admin-only enrollment ACEs are standard delegation noise. They
            # remain available in the raw DACL data, but should not become an
            # ESC13 entrypoint in the graph.
            enrollers = sorted({principal for _, principals in eligible_cas for principal in principals
                                if not adcs_default_admin_principal(principal)})
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
