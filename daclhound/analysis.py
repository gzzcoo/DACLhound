"""Offline analysis of DACLhound graph datasets and effective permission paths."""
from __future__ import annotations

import json
import re
import io
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from .common import canonical_sid, scalar


def _analysis_node_key(node: dict[str, Any], domain: str) -> str:
    """Use directory identity, rather than display name, when combining datasets."""
    kind = scalar(node.get("type")).strip().casefold()
    if kind == "adcs_finding":
        # Finding nodes intentionally share a DN with their certificate template.
        return f"{domain.casefold()}:adcs-finding:{scalar(node.get('id')).casefold()}"
    dn = scalar(node.get("dn")).strip().casefold()
    if dn:
        return f"dn:{dn}"
    sid = scalar(node.get("sid")).strip().casefold()
    if sid:
        return f"sid:{sid}"
    return f"{domain.casefold()}:{scalar(node.get('id')).casefold()}"


def _analysis_node_sid(node: dict[str, Any]) -> str:
    """Return an object's SID, including the SID embedded in trustee placeholders."""
    sid = scalar(node.get("sid")).strip()
    if not sid:
        candidate = scalar(node.get("id")) or scalar(node.get("name"))
        match = re.search(r"(?:trustee::)?(S-1-[0-9-]+)", candidate, re.IGNORECASE)
        sid = match.group(1) if match else ""
    return sid.casefold()


def _analysis_domain(dataset: dict[str, Any], filename: str) -> str:
    """Prefer the domain object's DN if the dataset's label is stale or generic."""
    for node in dataset.get("nodes", []):
        if not isinstance(node, dict) or scalar(node.get("type")).casefold() != "domain":
            continue
        components = re.findall(r"(?:^|,)\s*DC=([^,]+)", scalar(node.get("dn")), re.IGNORECASE)
        if components:
            return ".".join(components)
    return scalar(dataset.get("domain")) or Path(filename).stem


def _analysis_edge_label(edge: dict[str, Any]) -> str:
    """Render only the actionable parts of an ACE in a short path label."""
    kind = scalar(edge.get("kind"))
    if kind == "ownership":
        return "Owns"
    if kind == "sql_admin":
        return "SQLAdmin"
    if kind == "delegation":
        return "AllowedToAct" if scalar(edge.get("delegationType")).casefold() == "rbcd" else "AllowedToDelegate"
    if kind == "membership":
        return "MemberOf"
    if kind == "sid_history":
        return "HasSIDHistory"
    if kind == "gpo_link":
        return "GPLink"
    if kind == "enterprise_ca_for":
        return "EnterpriseCAFor"
    if kind == "root_ca_for":
        return "RootCAFor"
    if kind == "adcs_policy_link":
        return "IssuancePolicy"
    if kind == "adcs_template_link":
        return "UsesTemplate"
    if kind == "oid_group_link":
        return "LinkedGroups"
    if kind == "adcs_esc":
        return scalar(edge.get("adcsEdgeLabel")) or ("ADCSESC13" if scalar(edge.get("esc")).upper() == "ESC13" else f"ADCS {scalar(edge.get('esc'))}")
    right = scalar(edge.get("right"))
    object_type = scalar(edge.get("objectType"))
    raw_ace = edge.get("raw") if isinstance(edge.get("raw"), dict) else {}
    object_guid = scalar(raw_ace.get("ObjectTypeGuid") or edge.get("objectTypeGuid")).strip("{}").casefold()
    normalized_object_type = object_type.casefold().replace("-", "")
    if edge.get("gmsaPasswordRead") or "msdsmanagedpassword" in normalized_object_type:
        return "ReadGMSAPassword"
    if edge.get("lapsPasswordRead") or "mslaps" in normalized_object_type or "ms-mcs-admpwd" in object_type.casefold() or object_type.strip("{}").casefold() in {
        "4ed65179-900d-4f23-b391-f04f1d188347", "6dbd0ce5-699e-48c6-898d-5f7f59bef1c7",
        "e4e2e944-4077-46f2-963c-9c404f2caf32",
    }:
        return "ReadLAPSPassword"
    normalized = re.sub(r"[^a-z0-9]", "", object_type.casefold())
    tokens = {token.strip().upper() for token in right.split("|") if token.strip()}
    if "GENERIC_ALL" in tokens:
        return "GenericAll"
    if "GENERIC_WRITE" in tokens:
        return "GenericWrite"
    if "WRITE_DACL" in tokens:
        return "WriteDacl"
    if "WRITE_OWNER" in tokens:
        return "WriteOwner"
    if "CREATE_CHILD" in tokens and "DELETE_CHILD" in tokens:
        return "CreateChild / DeleteChild"
    if "DELETE_CHILD" in tokens:
        return "DeleteChild"
    if "DELETE_TREE" in tokens:
        return "DeleteTree"
    if "DELETE" in tokens:
        return "Delete"
    if "WRITE_VALIDATED" in tokens:
        if scalar(edge.get("targetType")).casefold() == "group" and normalized in {
            "member", "memberselfmembership", "self", "bf9679c00de611d0a28500aa003049e2",
        }:
            return "AddSelf"
        return "ValidatedSPN" if "spn" in object_type.casefold() else "ValidatedWrite"
    if "CONTROL_ACCESS" in tokens:
        extended_right_guids = {
            "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "RestoreDeletedObjects",
            "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
            "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
        }
        if object_guid in extended_right_guids:
            return extended_right_guids[object_guid]
        for marker, label in (
            ("reanimate-tombstones", "RestoreDeletedObjects"),
            ("reanimatetombstones", "RestoreDeletedObjects"),
            ("force-change-password", "ForceChangePassword"),
            ("reset-password", "ForceChangePassword"),
            ("resetpassword", "ForceChangePassword"),
            ("replication-get-changes-in-filtered-set", "GetChangesInFilteredSet"),
            ("replication-get-changes-all", "GetChangesAll"),
            ("replication-get-changes", "GetChanges"),
            ("all-extended-rights", "AllExtendedRights"),
            ("manage-ca", "ManageCA"),
            ("manage-certificates", "ManageCertificates"),
            ("certificate-enrollment", "Enroll"),
            ("certificate enrollment", "Enroll"),
            ("enrollment", "Enroll"),
        ):
            if marker in object_type.casefold():
                return label
    mapping = {
        "GENERIC_ALL": "GenericAll", "GENERIC_WRITE": "GenericWrite",
        "WRITE_DACL": "WriteDacl", "WRITE_OWNER": "WriteOwner",
        "WRITE_PROP": "WriteProperty", "WRITE_VALIDATED": "WriteValidated",
        "CONTROL_ACCESS": "ControlAccess", "CREATE_CHILD": "CreateChild",
        "DELETE_CHILD": "DeleteChild", "DELETE_TREE": "DeleteTree",
        "DELETE": "Delete", "ADD_MEMBER": "AddMember", "ADD_SELF": "AddSelf",
        "FORCECHANGEPASSWORD": "ForceChangePassword", "OWNERSHIP": "Owns",
    }
    display = [mapping[token.strip().upper()] for token in right.split("|") if token.strip() and token.strip().upper() in mapping]
    # Broad rights make redundant component rights unhelpful in the display.
    if "GenericAll" in display:
        display = ["GenericAll"]
    elif "GenericWrite" in display:
        display = [token for token in display if token not in {"WriteProperty", "WriteValidated"}]
    label = "/".join(dict.fromkeys(display)) or scalar(edge.get("esc")) or right or "Permission"
    if "WRITE_PROP" in tokens:
        if normalized == "sidhistory":
            return "SpoofSIDHistory"
        if object_type.strip().casefold() == "self":
            return "GenericWrite"
        if object_type.strip().casefold() == "rdn":
            return "WriteDN"
        properties = (
            ("useraccountcontrol", "WriteUserAccountControl"), ("logonhours", "WriteLogonHours"),
            ("serviceprincipalname", "WriteSPN"), ("gplink", "WriteGPLink"),
            ("mspkicertificatenameflag", "WritePKINameFlag"), ("mspkienrollmentflag", "WritePKIEnrollmentFlag"),
            ("publicinformation", "WritePublicInformation"), ("accountrestrictions", "WriteAccountRestrictions"),
            ("msdskeycredentiallink", "AddKeyCredentialLink"),
            ("msdsallowedtoactonbehalfofotheridentity", "AddAllowedToAct"),
            ("msdsgroupmsamembership", "WriteMSDSGroupMSAMembership"), ("member", "AddMember"),
            ("scriptpath", "WriteScriptPath"), ("altsecurityidentities", "WriteAltSecurityIdentities"),
            ("userprincipalname", "WriteUPN"), ("grouptype", "WriteGroupType"),
            ("ntsecuritydescriptor", "WriteSecurityDescriptor"),
        )
        for marker, property_label in properties:
            if marker in normalized:
                return property_label
        attribute = re.sub(r"\s*\(property set\)\s*", "", object_type, flags=re.IGNORECASE)
        attribute = re.sub(r"[^a-zA-Z0-9]", "", attribute)
        if attribute:
            return "Write" + attribute[:1].upper() + attribute[1:]
    if object_type and "WriteProperty" in display:
        label += f" [{object_type}]"
    return label


def _analysis_actionable(edge: dict[str, Any]) -> bool:
    """Match the graph's default interesting-permission filter."""
    if "DENIED" in scalar(edge.get("type")).upper():
        return False
    kind = scalar(edge.get("kind"))
    if edge.get("gmsaPasswordRead") or edge.get("lapsPasswordRead"):
        return True
    if kind in {"gpo_link", "adcs_esc", "adcs_policy_link", "adcs_template_link", "oid_group_link",
                "delegation", "sql_admin", "ownership", "sid_history", "enterprise_ca_for", "root_ca_for",
                "domain_trust"}:
        return True
    if kind != "dacl":
        return False
    right = scalar(edge.get("right")).upper()
    object_type = scalar(edge.get("objectType")).strip().casefold()
    normalized = re.sub(r"[^a-z0-9]", "", object_type)
    if "msds-managedpassword" in normalized or any(attribute in normalized for attribute in (
        "msmcsadmpwd", "mslapspassword", "mslapsencryptedpassword", "mslapsencryptedpasswordhistory",
    )):
        return True
    if re.search(r"GENERIC_ALL|GENERIC_WRITE|WRITE_DACL|WRITE_OWNER|DELETE_CHILD|DELETE_TREE|\bDELETE\b", right):
        return True
    if "CREATE_CHILD" in right and scalar(edge.get("targetType")).casefold() in {"ou", "container", "domain"}:
        return True
    if "ACCESS_SYSTEM_SECURITY" in right:
        return True
    raw = edge.get("raw") if isinstance(edge.get("raw"), dict) else {}
    object_guid = scalar(raw.get("ObjectTypeGuid") or edge.get("objectTypeGuid")).strip("{}").casefold()
    if ("CONTROL_ACCESS" in right and re.search(
        r"reanimate[- ]tombstones|reanimatetombstones|force-change-password|reset[- ]password|resetpassword|replication-get-changes|all-extended-rights|add-self|apply-group-policy|manage-ca|manage-certificates|certificate-enrollment",
        object_type,
    )) or ("CONTROL_ACCESS" in right and object_guid in {
        "45ec5156-db7e-47bb-b53f-dbeb2d03c40f", "00299570-246d-11d0-a768-00aa006e0529",
        "0e10c968-78fb-11d2-90d4-00c04f79dc55",
    }):
        return True
    if "WRITE_VALIDATED" in right:
        validated_scope = re.sub(r"[^a-z0-9]", "", object_type)
        self_membership = scalar(edge.get("targetType")).casefold() == "group" and validated_scope in {
            "member", "memberselfmembership", "self", "bf9679c00de611d0a28500aa003049e2",
        }
        return (self_membership
                or bool(re.search(r"validated-write-computer|validated-spn|validated-dns-host-name", object_type)))
    if "WRITE_PROP" in right:
        if normalized == "pwdlastset":
            return False
        if object_type == "self":
            return True
        if not object_type:
            return False
        if "(property set)" in object_type:
            return bool(re.search(r"public-information|account-restrictions", object_type))
        return True
    if "READ_PROP" in right:
        if object_type.strip("{}") in {
            "4ed65179-900d-4f23-b391-f04f1d188347", "6dbd0ce5-699e-48c6-898d-5f7f59bef1c7",
            "e4e2e944-4077-46f2-963c-9c404f2caf32",
        }:
            return True
        return any(attribute in normalized for attribute in (
            "msdsmanagedpassword", "msmcsadmpwd", "mslapspassword",
            "mslapsencryptedpassword", "mslapsencryptedpasswordhistory",
        ))
    return False


def _analysis_common_dacl_trustee(value: str) -> bool:
    """Suppress the common trustee ACEs hidden by the graph's default filter."""
    common = {
        "everyone", "authenticated_users", "authenticated users", "principal_self", "principal self",
        "creator_owner", "creator owner", "local_system", "local system", "nt authority\\system",
        "builtin_administrators", "builtin administrators", "administrators", "account_operators",
        "account operators", "domain admins", "enterprise admins", "enterprise read-only domain controllers",
        "enterprise_read_only_domain_controllers", "enterprise_domain_controllers", "enterprise domain controllers",
        "alias_prew2kcompacc", "pre-windows 2000 compatible access", "ras and ias servers",
        "windows_authorization_access_group", "windows authorization access group",
        "terminal_server_license_servers", "terminal server license servers", "cert publishers",
        "key admins", "enterprise key admins", "domain users", "domain computers", "domain controllers",
        "domain guests", "read-only domain controllers", "denied rodc password replication group", "guests",
        "users", "schema admins", "group policy creator owners", "server operators", "backup operators",
        "print operators", "printer_operators", "replicator", "dnsadmins", "dnsupdateproxy",
    }
    parts = [part.strip().casefold() for part in re.split(r"[;|]", value) if part.strip()]
    if not parts:
        return False
    for part in parts:
        if part in {"domain users", "domain computers"}:
            return False
        if part in common:
            continue
        if re.fullmatch(r"s-1-5-21-(?:\d+-){3}(?:498|512|513|514|515|516|518|519|520|521|526|527|553)", part):
            continue
        if re.fullmatch(r"s-1-5-(?:18|19|20|32-(?:544|548|549|550|551|552|554|555|556|557|558|559|560|562|568|569|573|574|575|576|577|578|579|580|581|582|583|584|585|586|587|588|589|590|591|592|593|594|595|596|597|598|599))", part):
            continue
        return False
    return True


def _analysis_can_pivot(edge: dict[str, Any]) -> bool:
    """Only continue through rights that can plausibly yield control of a principal."""
    if scalar(edge.get("kind")) == "ownership":
        return True
    tokens = {token.strip().upper() for token in scalar(edge.get("right")).split("|")}
    if tokens.intersection({"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER",
                            "ADD_MEMBER", "ADD_SELF", "FORCECHANGEPASSWORD"}):
        return True
    object_type = scalar(edge.get("objectType")).casefold().replace("-", "")
    if "userforcechangepassword" in object_type or "msdsmanagedpassword" in object_type:
        return True
    if "ms-mcs-admpwd" in scalar(edge.get("objectType")).casefold() or "mslaps-password" in object_type:
        return True
    if "WRITE_VALIDATED" in tokens and scalar(edge.get("targetType")).casefold() == "group":
        if re.sub(r"[^a-z0-9]", "", scalar(edge.get("objectType")).casefold()) in {
            "self", "member", "memberselfmembership", "bf9679c00de611d0a28500aa003049e2",
        }:
            return True
    if "WRITE_PROP" in tokens or "WRITE_VALIDATED" in tokens:
        pivot_attributes = (
            "serviceprincipalname", "msds-keycredentiallink",
            "msds-allowedtoactonbehalfofotheridentity", "msds-groupmsamembership",
            "useraccountcontrol", "member", "scriptpath",
        )
        return any(attribute in object_type for attribute in pivot_attributes)
    return False


def _render_analysis_report(paths: list[str], from_user: str | None, limit: int, color_mode: str = "auto") -> int:
    """Find effective permission chains offline, following group membership and ACL edges."""
    nodes: dict[str, dict[str, Any]] = {}
    scoped_ids: dict[tuple[str, str], str] = {}
    raw_edges: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    domains_seen: set[str] = set()
    for filename in paths:
        try:
            with open(filename, "r", encoding="utf-8") as graph_file:
                dataset = json.load(graph_file)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not read graph JSON {filename}: {exc}") from exc
        if not isinstance(dataset, dict) or not isinstance(dataset.get("nodes"), list) or not isinstance(dataset.get("edges"), list):
            raise RuntimeError(f"{filename} is not a normalized DACLhound graph JSON")
        if dataset.get("schema") not in (None, "daclgraph/v1"):
            raise RuntimeError(f"Unsupported graph schema in {filename}: {dataset.get('schema')}")

        domain = _analysis_domain(dataset, filename)
        domains_seen.add(domain)
        for node in dataset["nodes"]:
            if not isinstance(node, dict):
                continue
            key = _analysis_node_key(node, domain)
            scoped_ids[(domain.casefold(), scalar(node.get("id")))] = key
            current = nodes.setdefault(key, dict(node))
            current["__domain"] = _analysis_domain({"nodes": [node], "domain": domain}, filename)
        for edge in dataset["edges"]:
            if not isinstance(edge, dict):
                continue
            edge_id = scalar(edge.get("id")) or json.dumps(edge, sort_keys=True, ensure_ascii=False)
            key = (domain.casefold(), edge_id)
            raw_edges.setdefault(key, (domain.casefold(), dict(edge)))

    by_id = {key: node for key, node in nodes.items()}
    # A trustee placeholder can hold only a SID in one forest while the actual
    # user/group/computer node is present in another loaded graph. Resolve the
    # SID across the whole input set before constructing permission paths.
    sid_index: dict[str, str] = {}
    trustee_aliases: dict[str, str] = {}
    for key, node in by_id.items():
        sid = _analysis_node_sid(node)
        # Domain SIDs are unique across forests; well-known SIDs such as
        # BUILTIN\Administrators repeat in every domain and must stay scoped.
        if sid.startswith("s-1-5-21-") and scalar(node.get("type")).casefold() != "trustee":
            sid_index.setdefault(sid, key)
    for key, node in by_id.items():
        if scalar(node.get("type")).casefold() != "trustee":
            continue
        sid = _analysis_node_sid(node)
        resolved = sid_index.get(sid) if sid else None
        if resolved:
            trustee_aliases[key] = resolved

    def resolve_endpoint(domain: str, raw_id: str) -> str:
        local = scoped_ids.get((domain, raw_id))
        if local:
            return trustee_aliases.get(local, local)
        sid = _analysis_node_sid({"id": raw_id})
        if sid and sid in sid_index:
            return sid_index[sid]
        return f"{domain}:{raw_id}"

    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for edge_key, (domain, original) in raw_edges.items():
        normalized = dict(original)
        normalized["__source"] = resolve_endpoint(domain, scalar(original.get("source")))
        normalized["__target"] = resolve_endpoint(domain, scalar(original.get("target")))
        edges[edge_key] = normalized

    members_of: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    actions: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    visible_relationships: list[tuple[str, str, dict[str, Any]]] = []
    for edge in edges.values():
        source, target = edge["__source"], edge["__target"]
        if edge.get("kind") == "membership":
            members_of.setdefault(source, []).append((target, edge))
            continue
        source_node, target_node = by_id.get(source, {}), by_id.get(target, {})
        if source_node.get("type") == "user" and (
            scalar(source_node.get("name")).strip().casefold() == "administrator"
            or scalar(source_node.get("sid")).endswith("-500")
        ):
            continue
        if target_node.get("type") == "user" and (
            scalar(target_node.get("name")).strip().casefold() == "administrator"
            or scalar(target_node.get("sid")).endswith("-500")
        ):
            continue
        kind = scalar(edge.get("kind"))
        if kind == "gpo_link" and scalar(edge.get("targetName")).strip().casefold() in {
            "default domain policy", "default domain controllers policy",
        }:
            continue
        special_visible = {"delegation", "sql_admin", "adcs_esc"}
        relationship_links = {
            "gpo_link", "sid_history", "enterprise_ca_for", "root_ca_for", "domain_trust",
            "adcs_policy_link", "adcs_template_link", "oid_group_link",
        }
        if kind not in special_visible | relationship_links:
            trustee_name = scalar(edge.get("sourceName")) or scalar(edge.get("source"))
            if source_node and scalar(source_node.get("type")).casefold() != "trustee":
                trustee_name = scalar(source_node.get("samAccountName")) or scalar(source_node.get("name")) or trustee_name
            if _analysis_common_dacl_trustee(trustee_name):
                continue
        if kind == "dacl":
            if (scalar(edge.get("targetType")).casefold() == "cert_template"
                    and scalar(edge.get("objectType")).casefold() == "certificate-enrollment"):
                continue
            if re.search(r"(?:^|[;|])\s*INHERIT_ONLY(?:$|[;|])", scalar(edge.get("flags")), re.IGNORECASE):
                if scalar(edge.get("targetType")).casefold() not in {"ou", "container", "domain"}:
                    continue
        if _analysis_actionable(edge):
            visible_relationships.append((source, target, edge))
            actions.setdefault(source, []).append((target, edge))

    def label(node_id: str) -> str:
        node = by_id.get(node_id, {})
        name = (scalar(node.get("name")) if node.get("type") == "adcs_finding" else "") or scalar(node.get("samAccountName")) or scalar(node.get("name")) or scalar(node.get("id")) or node_id
        domain = scalar(node.get("__domain"))
        return f"{name}@{domain}" if domain and "@" not in name else name

    def typed_label(node_id: str) -> str:
        node = by_id.get(node_id, {})
        type_names = {
            "user": "User", "group": "Group", "computer": "Computer", "ou": "OU",
            "gpo": "GPO", "domain": "Domain", "container": "Container",
            "cert_template": "Certificate Template", "enterprise_ca": "Enterprise CA",
            "root_ca": "Root CA", "trustee": "Trustee", "service": "Service",
            "trusted_domain": "Trusted Domain", "adcs_finding": "ADCS Finding",
        }
        object_type = type_names.get(scalar(node.get("type")).casefold())
        return f"{label(node_id)} ({object_type})" if object_type else label(node_id)

    ids_by_typed_label: dict[str, list[str]] = {}
    for node_id in by_id:
        ids_by_typed_label.setdefault(typed_label(node_id), []).append(node_id)

    def descendant_of(child_label: str, parent_label: str) -> bool:
        for child_id in ids_by_typed_label.get(child_label, []):
            child_dn = scalar(by_id.get(child_id, {}).get("dn")).casefold().rstrip(",")
            if not child_dn:
                continue
            for parent_id in ids_by_typed_label.get(parent_label, []):
                parent_dn = scalar(by_id.get(parent_id, {}).get("dn")).casefold().rstrip(",")
                if parent_dn and child_dn.endswith("," + parent_dn):
                    return True
        return False

    def is_inheritable_scope(edge_name: str, target_name: str) -> bool:
        return edge_name.endswith("(inheritable)") and any(
            scalar(by_id.get(node_id, {}).get("type")).casefold() in {"ou", "container", "domain"}
            for node_id in ids_by_typed_label.get(target_name, [])
        )

    def display_edge_label(edge: dict[str, Any], target_id: str) -> str:
        base = _analysis_edge_label(edge)
        if scalar(edge.get("kind")).casefold() != "dacl":
            return base
        flags = {part.strip().upper() for part in re.split(r"[;|,]", scalar(edge.get("flags"))) if part.strip()}
        if edge.get("inherited") is True or "INHERITED" in flags:
            return f"{base} (inherited)"
        if "INHERIT_ONLY" in flags:
            return f"{base} (inherit-only)"
        target_type = scalar(by_id.get(target_id, {}).get("type")).casefold()
        if target_type in {"ou", "container", "domain"} and flags & {"CONTAINER_INHERIT", "OBJECT_INHERIT"}:
            return f"{base} (inheritable)"
        return base

    def matches(user: str) -> list[str]:
        wanted = user.casefold()
        found = []
        for key, node in by_id.items():
            if scalar(node.get("type")).casefold() != "user":
                continue
            sam = scalar(node.get("samAccountName"))
            name = scalar(node.get("name"))
            full = f"{sam or name}@{scalar(node.get('__domain'))}".casefold()
            if wanted in {key.casefold(), scalar(node.get("sid")).casefold(),
                          scalar(node.get("dn")).casefold(), sam.casefold(), name.casefold(), full}:
                found.append(key)
        return sorted(set(found))

    if from_user:
        starts = matches(from_user)
    else:
        # The default analysis should answer the useful question: which users
        # can reach actionable rights through their group memberships? A flat
        # edge dump is already available in the graph viewer and hides these
        # effective paths.
        starts = sorted(
            key for key, node in by_id.items()
            if scalar(node.get("type")).casefold() == "user"
            and scalar(node.get("name")).strip().casefold() != "administrator"
            and not scalar(node.get("sid")).endswith("-500")
        )
    if from_user and not starts:
        available = sorted({
            f"{scalar(node.get('samAccountName')) or scalar(node.get('name'))}@{scalar(node.get('__domain'))}"
            for node in by_id.values() if scalar(node.get("type")).casefold() == "user"
        })
        suggestions = ", ".join(available[:8])
        raise RuntimeError(f"No user matched '{from_user}'. Available users include: {suggestions}")
    if from_user and len(starts) > 1:
        choices = ", ".join(label(key) for key in starts)
        raise RuntimeError(f"'{from_user}' matches multiple users; use a domain-qualified name: {choices}")

    found_paths: set[tuple[str, ...]] = set()
    path_permission_edges: set[tuple[str, str, str]] = set()
    for start in starts:
        # Each queue item is a principal plus the rendered edge/node sequence.
        queue: list[tuple[str, tuple[str, ...], frozenset[str]]] = [(start, (typed_label(start),), frozenset({start}))]
        visited_principals = {start}
        cursor = 0
        while cursor < len(queue):
            current, route, visited = queue[cursor]
            cursor += 1
            for group_id, _membership in members_of.get(current, []):
                group = by_id.get(group_id, {})
                if scalar(group.get("type")).casefold() != "group" or group_id in visited_principals:
                    continue
                next_route = route + ("MemberOf", typed_label(group_id))
                visited_principals.add(group_id)
                queue.append((group_id, next_route, visited | {group_id}))
            for target_id, edge in actions.get(current, []):
                if target_id == current:
                    continue
                target = by_id.get(target_id, {})
                edge_label = _analysis_edge_label(edge)
                next_route = route + (display_edge_label(edge, target_id), typed_label(target_id))
                found_paths.add(next_route)
                path_permission_edges.add((current, target_id, edge_label))
                if (_analysis_can_pivot(edge) and scalar(target.get("type")).casefold() in {"user", "group", "computer"}
                        and target_id not in visited_principals):
                    visited_principals.add(target_id)
                    queue.append((target_id, next_route, visited | {target_id}))

    # Match the viewer's default "Important group memberships only" setting so
    # the CLI also shows useful graph context that is not itself an ACL path.
    important_names = {
        "administrators", "domain admins", "enterprise admins", "schema admins", "account operators",
        "backup operators", "server operators", "print operators", "remote desktop users",
        "remote management users", "distributed com users", "event log readers",
        "certificate service dcom access", "hyper-v administrators", "access control assistance operators",
        "storage replica administrators", "dnsadmins", "key admins", "enterprise key admins", "protected users",
        "domain computers",
    }
    important_builtin_sids = {
        "s-1-5-32-544", "s-1-5-32-548", "s-1-5-32-549", "s-1-5-32-550", "s-1-5-32-551",
        "s-1-5-32-555", "s-1-5-32-556", "s-1-5-32-558", "s-1-5-32-559", "s-1-5-32-562",
        "s-1-5-32-568", "s-1-5-32-569", "s-1-5-32-573", "s-1-5-32-574", "s-1-5-32-575",
        "s-1-5-32-576", "s-1-5-32-577", "s-1-5-32-578", "s-1-5-32-579", "s-1-5-32-580",
        "s-1-5-32-582",
    }

    def group_name(node: dict[str, Any]) -> str:
        return (scalar(node.get("samAccountName")) or scalar(node.get("name"))).casefold()

    def special_admin_group(node: dict[str, Any]) -> bool:
        sid = scalar(node.get("sid")).casefold()
        return group_name(node) in {"administrators", "domain admins", "enterprise admins"} \
            or sid == "s-1-5-32-544" or sid.endswith(("-512", "-519"))

    def important_group(node: dict[str, Any]) -> bool:
        sid = scalar(node.get("sid")).casefold()
        name = group_name(node)
        return name == "domain computers" or name in important_names or sid in important_builtin_sids \
            or sid.endswith(("-515", "-512", "-516", "-518", "-519", "-520", "-521", "-526", "-527",
                             "-548", "-549", "-550", "-551", "-552"))

    membership_rows = [
        (member, group, edge)
        for member, memberships in members_of.items()
        for group, edge in memberships
    ]
    members_by_group: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
    memberships_by_member: dict[str, list[str]] = {}
    for member, group, edge in membership_rows:
        members_by_group.setdefault(group, []).append((member, group, edge))
        memberships_by_member.setdefault(member, []).append(group)

    groups_with_nonadmin_users: set[str] = set()
    for user_id, user in by_id.items():
        if scalar(user.get("type")).casefold() != "user":
            continue
        if scalar(user.get("name")).strip().casefold() == "administrator" or scalar(user.get("sid")).endswith("-500"):
            continue
        queue, visited = [user_id], {user_id}
        while queue:
            for group_id in memberships_by_member.get(queue.pop(0), []):
                group = by_id.get(group_id, {})
                if scalar(group.get("type")).casefold() != "group":
                    continue
                groups_with_nonadmin_users.add(group_id)
                if group_id not in visited:
                    visited.add(group_id)
                    queue.append(group_id)

    relevant_admin_memberships: set[str] = set()
    for group_id in (item for item in groups_with_nonadmin_users if special_admin_group(by_id.get(item, {}))):
        queue, visited = [group_id], {group_id}
        while queue:
            for member, _group, edge in members_by_group.get(queue.pop(0), []):
                edge_id = scalar(edge.get("id")) or f"{member}\0{_group}"
                relevant_admin_memberships.add(edge_id)
                if scalar(by_id.get(member, {}).get("type")).casefold() == "group" and member not in visited:
                    visited.add(member)
                    queue.append(member)

    acl_principal_groups = {
        source for source, _target, _edge in visible_relationships
        if scalar(by_id.get(source, {}).get("type")).casefold() == "group"
    }
    groups_with_acl_context = set(acl_principal_groups)
    queue = list(acl_principal_groups)
    while queue:
        for member, _group, _edge in members_by_group.get(queue.pop(), []):
            if scalar(by_id.get(member, {}).get("type")).casefold() == "group" and member not in groups_with_acl_context:
                groups_with_acl_context.add(member)
                queue.append(member)

    visible_acl_pairs = {(source, target) for source, target, _edge in visible_relationships}
    path_memberships: set[tuple[str, str]] = set()
    for route in found_paths:
        for index in range(1, len(route) - 1, 2):
            if route[index] == "MemberOf":
                path_memberships.add((route[index - 1], route[index + 1]))

    other_memberships: list[tuple[str, str]] = []
    for member, group, edge in membership_rows:
        member_node, group_node = by_id.get(member, {}), by_id.get(group, {})
        edge_id = scalar(edge.get("id")) or f"{member}\0{group}"
        member_is_admin = (
            scalar(member_node.get("type")).casefold() == "user"
            and (scalar(member_node.get("name")).strip().casefold() == "administrator"
                 or scalar(member_node.get("sid")).endswith("-500"))
        )
        group_is_special = special_admin_group(group_node)
        if group_is_special and group not in groups_with_nonadmin_users:
            continue
        if special_admin_group(member_node) and member not in groups_with_nonadmin_users:
            continue
        if member_is_admin and edge_id not in relevant_admin_memberships:
            continue
        member_sid, group_sid = scalar(member_node.get("sid")).casefold(), scalar(group_node.get("sid")).casefold()
        default_membership = member_sid.endswith("-500") and group_sid.endswith("-512") \
            or member_sid.endswith("-501") and group_sid.endswith("-514")
        if default_membership and edge_id not in relevant_admin_memberships:
            continue
        if not important_group(group_node) and edge_id not in relevant_admin_memberships:
            continue
        if (group, member) in visible_acl_pairs:
            continue
        keep_group = group in groups_with_acl_context or not _analysis_common_dacl_trustee(
            scalar(group_node.get("samAccountName")) or scalar(group_node.get("name"))
        ) or important_group(group_node) or group_is_special
        if not keep_group or (member, group) in path_memberships:
            continue
        other_memberships.append((member, group))

    def edges_for_membership(index: dict[str, list[tuple[str, dict[str, Any]]]]):
        for member_id, memberships in index.items():
            for group_id, relationship in memberships:
                yield member_id, group_id, relationship

    def path_priority(route: tuple[str, ...]) -> tuple[int, int, tuple[str, ...]]:
        joined = " ".join(route).casefold()
        priority = ("genericall", "forcechangepassword", "writedacl", "writeowner", "genericwrite",
                    "addmember", "addself", "controlaccess", "writeproperty", "writevalidated",
                    "createchild", "deletechild", "delete", "allowedtoact", "allowedtodelegate")
        rank = next((index for index, word in enumerate(priority) if word in joined), len(priority))
        return rank, len(route), tuple(part.casefold() for part in route)

    ranked = sorted(found_paths, key=path_priority)
    if not ranked and from_user:
        print("No actionable permission paths found for the collected users.")
        return 0

    color_enabled = color_mode != "never"

    def paint(value: str, *codes: str) -> str:
        if not color_enabled or not codes:
            return value
        return f"\033[{';'.join(codes)}m{value}\033[0m"

    def permission_color(value: str) -> str:
        normalized = value.casefold()
        if any(word in normalized for word in (
            "esc", "genericall", "writedacl", "writeowner", "forcechangepassword",
            "readgmsapassword", "readlapspassword", "allowedtodelegate", "allowedtoact",
            "addkeycredentiallink", "unconstraineddelegation", "constraineddelegation",
        )):
            return paint(value, "1", "31")
        if any(word in normalized for word in ("genericwrite", "write", "owns", "addmember", "addself", "delete")):
            return paint(value, "1", "33")
        if normalized == "memberof":
            return paint(value, "35")
        if normalized in {"gplink", "linkedgroups", "enterprisecafor", "rootcafor", "issuancepolicy", "usestemplate"}:
            return paint(value, "35")
        return paint(value, "32")

    domain_display = ", ".join(item.upper() for item in sorted(domains_seen, key=str.casefold))
    print(paint("DACLhound · Permission analysis", "1", "36"))
    print(f"{paint('Domains:', '35')} {domain_display}")

    def print_tree(routes: list[tuple[str, ...]], prefix: str = "  ") -> None:
        tree: dict[str, Any] = {"children": {}}
        for route in routes:
            cursor = tree
            for index in range(0, len(route) - 1, 2):
                edge_name, target_name = route[index], route[index + 1]
                cursor = cursor["children"].setdefault((edge_name, target_name), {"children": {}})

        def nest_inherited_descendants(current: dict[str, Any]) -> None:
            children = current["children"]
            scopes = [
                (key, value) for key, value in children.items()
                if is_inheritable_scope(key[0], key[1])
            ]
            for inherited_key, inherited_node in list(children.items()):
                if not inherited_key[0].endswith("(inherited)"):
                    continue
                matching_scopes = [
                    (scope_key, scope_node)
                    for scope_key, scope_node in scopes
                    if descendant_of(inherited_key[1], scope_key[1])
                ]
                if not matching_scopes:
                    continue
                scope_key, scope_node = max(
                    matching_scopes,
                    key=lambda item: max(
                        (len(scalar(by_id.get(node_id, {}).get("dn")))
                         for node_id in ids_by_typed_label.get(item[0][1], [])),
                        default=0,
                    ),
                )
                if inherited_key == scope_key:
                    continue
                children.pop(inherited_key, None)
                scope_node["children"].setdefault(inherited_key, inherited_node)
            for child_node in children.values():
                nest_inherited_descendants(child_node)

        nest_inherited_descendants(tree)

        def walk(current: dict[str, Any], indent: str) -> None:
            children = list(current["children"].items())
            for index, ((edge_name, target_name), child) in enumerate(children):
                last = index == len(children) - 1
                branch = "└─ " if last else "├─ "
                print(f"{paint(indent + branch, '90')}{permission_color(edge_name)} → {target_name}")
                if child["children"]:
                    walk(child, indent + ("   " if last else "│  "))

        walk(tree, prefix)

    def print_path_section(title: str | None, routes: list[tuple[str, ...]]) -> None:
        if not routes:
            return
        if title:
            print("\n" + paint(title, "1", "36"))
        if from_user:
            print(f"  Starting principal: {paint(typed_label(starts[0]), '1')}")
            print_tree([route[1:] for route in routes])
            return

        # Share each membership prefix across users so a group ACL is printed
        # once with its effective members, instead of once per account.
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for route in routes:
            if len(route) >= 3 and route[1] == "MemberOf":
                group = route[2]
                key = ("group", group)
                remaining = route[3:]
            else:
                key = ("direct", route[0])
                remaining = route[1:]
            entry = grouped.setdefault(key, {"principals": set(), "routes": set()})
            entry["principals"].add(route[0])
            entry["routes"].add(remaining)
        for (kind, principal), entry in sorted(grouped.items(), key=lambda item: item[0][1].casefold()):
            principal_label = principal
            heading = f"Effective paths via {principal_label}" if kind == "group" else f"Direct paths from {principal_label}"
            print(f"\n  {paint(heading, '1')}")
            if kind == "group":
                sources = sorted(entry["principals"], key=str.casefold)
                source_text = ", ".join(sources)
                print(f"    Effective members ({len(sources)}): {source_text}")
            print_tree(sorted(entry["routes"], key=path_priority), prefix="    ")

    selected_paths = ranked[:limit] if limit else ranked
    adcs_paths = [route for route in selected_paths if any("ESC" in route[index].upper() for index in range(1, len(route), 2))]
    ordinary_paths = [route for route in selected_paths if route not in adcs_paths]
    print_path_section("Effective permission paths", ordinary_paths)
    if limit and len(ranked) > limit:
        print(f"  ... {len(ranked) - limit} more paths omitted; increase --limit to show more")
    if not from_user and other_memberships:
        print("\n" + paint("Other visible group memberships", "1", "36"))
        members_by_display_group: dict[str, list[str]] = {}
        for member, group in other_memberships:
            members_by_display_group.setdefault(typed_label(group), []).append(typed_label(member))
        sorted_groups = sorted(members_by_display_group.items(), key=lambda item: item[0].casefold())
        for group_index, (group_label, member_labels) in enumerate(sorted_groups):
            print(f"  {paint(group_label, '1')}")
            unique_members = sorted(set(member_labels), key=str.casefold)
            print(f"    Direct members ({len(unique_members)}):")
            for member_label in unique_members:
                print(f"      {member_label}")
            if group_index + 1 < len(sorted_groups):
                print()

    roastable_accounts: list[tuple[str, list[str], list[str]]] = []
    for node_id, node in by_id.items():
        if scalar(node.get("type")).casefold() != "user":
            continue
        raw_flags = node.get("userAccountControl", [])
        raw_flags = raw_flags if isinstance(raw_flags, list) else [raw_flags]
        flags = {
            part.strip().upper()
            for value in raw_flags
            for part in re.split(r"[;|,]", scalar(value))
            if part.strip()
        }
        numeric_uac = 0
        for value in raw_flags:
            try:
                raw_value = scalar(value).strip()
                numeric_uac = int(raw_value, 0) if raw_value else 0
                if numeric_uac:
                    break
            except ValueError:
                continue
        enabled = node.get("enabled")
        is_disabled = enabled is False or scalar(enabled).strip().casefold() in {"false", "0", "no"}
        is_disabled = is_disabled or "ACCOUNTDISABLE" in flags or bool(numeric_uac & 0x2)
        if is_disabled:
            continue
        raw_spns = node.get("servicePrincipalNames") or node.get("servicePrincipalName") or []
        raw_spns = raw_spns if isinstance(raw_spns, list) else [raw_spns]
        spns = sorted({scalar(value).strip() for value in raw_spns if scalar(value).strip()}, key=str.casefold)
        explicit_asrep = node.get("asrepRoastable") is True or scalar(node.get("asrepRoastable")).strip().casefold() in {"true", "1", "yes"}
        explicit_kerberoast = node.get("kerberoastable") is True or scalar(node.get("kerberoastable")).strip().casefold() in {"true", "1", "yes"}
        asrep = explicit_asrep or bool({"DONT_REQ_PREAUTH", "DONT_REQUIRE_PREAUTH"} & flags) or bool(numeric_uac & 0x400000)
        kerberoast = explicit_kerberoast or bool(spns)
        if asrep or kerberoast:
            tags = (["AS-REP roastable"] if asrep else []) + (["Kerberoastable"] if kerberoast else [])
            roastable_accounts.append((label(node_id), tags, spns))
    if roastable_accounts:
        print("\n" + paint("Kerberos roasting", "1", "36"))
        for account, tags, spns in sorted(roastable_accounts, key=lambda item: item[0].casefold()):
            print(f"  {account}  {paint(' · '.join(tags), '1', '33')}")
            for spn in spns:
                print(f"    SPN: {spn}")

    delegations: dict[str, dict[str, Any]] = {}

    def delegation_record(principal_id: str) -> dict[str, Any]:
        return delegations.setdefault(principal_id, {
            "unconstrained": False, "constrained_spns": set(),
            "protocol_transition": False, "rbcd_targets": set(),
        })

    for node_id, node in by_id.items():
        if scalar(node.get("type")).casefold() not in {"user", "computer"}:
            continue
        if node.get("unconstrainedDelegation") is True:
            delegation_record(node_id)["unconstrained"] = True
        spns = node.get("allowedToDelegateTo") or []
        spns = spns if isinstance(spns, list) else [spns]
        if spns:
            record = delegation_record(node_id)
            record["constrained_spns"].update(scalar(spn).strip() for spn in spns if scalar(spn).strip())
            record["protocol_transition"] = node.get("protocolTransition") is True
    for _source, _target, edge in visible_relationships:
        if scalar(edge.get("kind")).casefold() != "delegation":
            continue
        source_id, target_id = scalar(edge.get("__source")), scalar(edge.get("__target"))
        delegation_type = scalar(edge.get("delegationType")).casefold()
        record = delegation_record(source_id)
        if delegation_type == "constrained":
            spns = edge.get("serviceSPNs") or [edge.get("objectType", "")]
            spns = spns if isinstance(spns, list) else [spns]
            record["constrained_spns"].update(scalar(spn).strip() for spn in spns if scalar(spn).strip())
            record["protocol_transition"] = record["protocol_transition"] or edge.get("protocolTransition") is True
        elif delegation_type == "rbcd":
            record["rbcd_targets"].add(typed_label(target_id))

    if delegations:
        print("\n" + paint("Delegations", "1", "36"))
        for principal_id, record in sorted(delegations.items(), key=lambda item: label(item[0]).casefold()):
            principal = typed_label(principal_id)
            if record["unconstrained"]:
                print(f"  {principal}  {paint('Unconstrained delegation', '1', '31')}")
            if record["constrained_spns"]:
                qualifier = " with protocol transition" if record["protocol_transition"] else ""
                print(f"  {principal}  {paint('Constrained delegation' + qualifier, '1', '31')}")
                for spn in sorted(record["constrained_spns"], key=str.casefold):
                    print(f"    SPN: {spn}")
            for target in sorted(record["rbcd_targets"], key=str.casefold):
                print(f"  {principal}  {paint('RBCD / AllowedToAct', '1', '31')} → {target}")

    if not from_user:
        nodes_by_domain: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        domain_nodes: dict[str, tuple[str, dict[str, Any]]] = {}
        for node_id, node in by_id.items():
            domain_name = scalar(node.get("__domain")).casefold()
            nodes_by_domain.setdefault(domain_name, []).append((node_id, node))
            if scalar(node.get("type")).casefold() == "domain":
                domain_nodes[domain_name] = (node_id, node)

        if domain_nodes:
            print("\n" + paint("Domain overview", "1", "36"))
            for domain_name, (_domain_id, domain_node) in sorted(domain_nodes.items()):
                counts: dict[str, int] = {}
                for _node_id, node in nodes_by_domain.get(domain_name, []):
                    kind = scalar(node.get("type")).casefold()
                    if kind in {"user", "computer", "group", "ou", "gpo"}:
                        counts[kind] = counts.get(kind, 0) + 1
                summary = ", ".join(
                    f"{count} {kind}{'s' if count != 1 else ''}"
                    for kind, count in (("user", counts.get("user", 0)),
                                        ("computer", counts.get("computer", 0)),
                                        ("group", counts.get("group", 0)),
                                        ("OU", counts.get("ou", 0)),
                                        ("GPO", counts.get("gpo", 0)))
                    if count
                )
                details = [f"SID: {scalar(domain_node.get('sid')) or 'unknown'}",
                           f"DN: {scalar(domain_node.get('dn')) or 'unknown'}"]
                print(f"  {paint(domain_name.upper(), '1')}  {summary}")
                print(f"    {' · '.join(details)}")

        reverse_memberships: dict[str, list[str]] = {}
        for member_id, groups in members_of.items():
            for group_id, _relationship in groups:
                reverse_memberships.setdefault(group_id, []).append(member_id)
        domain_admin_members: dict[str, dict[str, bool]] = {}
        for group_id, group_node in by_id.items():
            if scalar(group_node.get("type")).casefold() != "group":
                continue
            if (scalar(group_node.get("samAccountName") or group_node.get("name")).strip().casefold()
                    != "domain admins" and not scalar(group_node.get("sid")).casefold().endswith("-512")):
                continue
            direct_members = set(reverse_memberships.get(group_id, []))
            queue = list(direct_members)
            visited: set[str] = set()
            while queue:
                member_id = queue.pop()
                if member_id in visited:
                    continue
                visited.add(member_id)
                member_node = by_id.get(member_id, {})
                kind = scalar(member_node.get("type")).casefold()
                if kind == "user":
                    domain_name = scalar(group_node.get("__domain")).casefold()
                    members_for_domain = domain_admin_members.setdefault(domain_name, {})
                    members_for_domain[member_id] = members_for_domain.get(member_id, False) or member_id in direct_members
                elif kind == "group":
                    queue.extend(reverse_memberships.get(member_id, []))
        if domain_admin_members:
            print("\n" + paint("Domain Admins", "1", "36"))
            for domain_name, user_membership in sorted(domain_admin_members.items()):
                if not user_membership:
                    continue
                print(f"  {domain_name.upper()}")
                for user_id, is_direct in sorted(user_membership.items(), key=lambda item: label(item[0]).casefold()):
                    user_node = by_id.get(user_id, {})
                    membership = "direct" if is_direct else "nested"
                    status = "disabled" if user_node.get("enabled") is False else "enabled" if user_node.get("enabled") is True else "status unknown"
                    print(f"    {label(user_id)}  (User, {membership}, {status})")

        admin_count_objects = [
            (node_id, node) for node_id, node in by_id.items()
            if node.get("adminCount") is True or scalar(node.get("adminCount")).strip().casefold() in {"1", "true", "yes"}
        ]
        if admin_count_objects:
            print("\n" + paint("Objects with adminCount=1", "1", "36"))
            for node_id, node in sorted(admin_count_objects, key=lambda item: (scalar(item[1].get("type")).casefold(), label(item[0]).casefold())):
                details = [scalar(node.get("type")).replace("_", " ").title()]
                if scalar(node.get("enabled")).strip():
                    details.append("enabled" if node.get("enabled") is True else "disabled" if node.get("enabled") is False else "status unknown")
                print(f"  {label(node_id)}  ({', '.join(details)})")

        default_group_names = {
            "access control assistance operators", "account operators", "administrators",
            "allowed rodc password replication group", "backup operators", "cert publishers",
            "certificate service dcom access", "cloneable domain controllers", "cryptographic operators",
            "denied rodc password replication group", "distributed com users", "dnsadmins", "dnsupdateproxy",
            "domain admins", "domain computers", "domain controllers", "domain guests", "domain users",
            "enterprise admins", "enterprise key admins", "enterprise read-only domain controllers",
            "external trust accounts", "forest trust accounts",
            "event log readers", "guests", "hyper-v administrators", "iis_iusrs",
            "group policy creator owners", "incoming forest trust builders", "key admins", "network configuration operators",
            "performance log users", "performance monitor users", "pre-windows 2000 compatible access",
            "print operators", "protected users", "ras and ias servers", "rds endpoint servers",
            "rds management servers", "rds remote access servers", "read-only domain controllers",
            "remote desktop users", "remote management users", "replicator", "schema admins",
            "server operators", "storage replica administrators", "terminal server license servers",
            "windows authorization access group",
        }
        default_container_names = {
            "computers", "domain controllers", "foreignsecurityprincipals", "managed service accounts", "microsoft",
            "program data", "system", "users",
        }
        default_builtin_user_descriptions = {
            "administrator": "built-in account for administering the computer/domain",
            "guest": "built-in account for guest access to the computer/domain",
            "krbtgt": "key distribution center service account",
        }
        described_objects = [
            (node_id, node, re.sub(r"[\r\n]+", " ", scalar(node.get("description")).strip()))
            for node_id, node in by_id.items()
            if scalar(node.get("description")).strip()
            and not (
                scalar(node.get("type")).casefold() == "group"
                and (scalar(node.get("name") or node.get("samAccountName")).strip().casefold() in default_group_names
                     or re.search(r"(?:^|,)CN=Builtin(?:,|$)", scalar(node.get("dn")), re.IGNORECASE))
            )
            and not (
                scalar(node.get("type")).casefold() in {"container", "ou"}
                and scalar(node.get("name")).strip().casefold() in default_container_names
            )
            and not (
                scalar(node.get("type")).casefold() == "user"
                and scalar(node.get("description")).strip().casefold()
                    == default_builtin_user_descriptions.get(scalar(node.get("samAccountName") or node.get("name")).strip().casefold())
            )
        ]
        if described_objects:
            print("\n" + paint("Object descriptions", "1", "36"))
            description_limit = limit if limit else len(described_objects)
            shown_descriptions = sorted(described_objects, key=lambda item: label(item[0]).casefold())[:description_limit]
            for node_id, _node, description in shown_descriptions:
                print(f"  {paint(typed_label(node_id), '1')}")
                print(f"    {description}")
            if len(described_objects) > description_limit:
                print(f"  ... {len(described_objects) - description_limit} more descriptions omitted; increase --limit to show more")

    if from_user and ranked:
        print("These chains follow group membership and permission edges; validate each right and its target-specific effect before treating a chain as exploitable.")
    elif not from_user:
        remaining = []
        gpo_links: set[tuple[str, str]] = set()
        domain_trusts: set[tuple[str, str, str, str, str]] = set()
        adcs_findings: dict[str, dict[str, Any]] = {}
        pki_relationships: set[tuple[str, str, str]] = set()
        for source, target, edge in visible_relationships:
            kind = scalar(edge.get("kind"))
            if kind == "membership":
                continue
            if kind == "adcs_esc" and scalar(edge.get("esc")).upper() == "ESC5" and not edge.get("isACL"):
                source_node = by_id.get(source, {})
                flags = source_node.get("userAccountControl", [])
                flags = flags if isinstance(flags, list) else [flags]
                is_dc = (
                    source_node.get("type") == "computer"
                    and (scalar(source_node.get("primaryGroupID")) == "516"
                         or any(scalar(flag).upper() == "SERVER_TRUST_ACCOUNT" for flag in flags)
                         or bool(re.search(r"(?:^|,)OU=Domain Controllers(?:,|$)", scalar(source_node.get("dn")), re.I)))
                )
                if is_dc:
                    continue
            edge_source = scalar(edge.get("sourceName")) or label(source)
            source_label = typed_label(source) if source in by_id else edge_source

            if kind == "domain_trust":
                source_node = by_id.get(source, {})
                source_domain = (scalar(source_node.get("__domain"))
                                 or scalar(source_node.get("name")) or source_label).upper()
                partner = (scalar(edge.get("targetName"))
                           or scalar(by_id.get(target, {}).get("trustPartner"))
                           or label(target)).rstrip(".").upper()

                def prettify_trust_value(value: Any) -> str:
                    return ", ".join(
                        re.sub(r"^[A-Za-z][A-Za-z0-9_]*\.", "", part.strip()).replace("_", " ").title()
                        for part in scalar(value).split(";") if part.strip()
                    )

                direction = prettify_trust_value(edge.get("trustDirection", ""))
                trust_type = prettify_trust_value(edge.get("trustType", ""))
                trust_type = {
                    "ad": "Uplevel",
                    "local windows": "Downlevel",
                    "non windows": "MIT",
                }.get(trust_type.casefold(), trust_type)
                attributes = prettify_trust_value(edge.get("trustAttributes", ""))
                if direction.casefold() == "bidirectional":
                    left, right = sorted((source_domain, partner), key=str.casefold)
                    domain_trusts.add((left, right, direction, trust_type, attributes))
                else:
                    domain_trusts.add((source_domain, partner, direction, trust_type, attributes))
                continue
            if kind == "gpo_link":
                gpo_links.add((source_label, typed_label(target)))
                continue
            if kind == "adcs_esc":
                if (source, target, _analysis_edge_label(edge)) in path_permission_edges:
                    continue
                finding = adcs_findings.setdefault(target, {
                    "name": typed_label(target), "esc": scalar(edge.get("esc")).upper(),
                    "principals": set(), "linked_groups": set(),
                })
                finding["principals"].add(source_label)
                continue
            if kind == "oid_group_link":
                finding = adcs_findings.setdefault(source, {
                    "name": typed_label(source), "esc": "", "principals": set(), "linked_groups": set(),
                })
                finding["linked_groups"].add(typed_label(target))
                continue
            if kind in {"adcs_policy_link", "adcs_template_link", "enterprise_ca_for", "root_ca_for"}:
                pki_relationships.add((kind, source_label, typed_label(target)))
                continue
            if (source, target, _analysis_edge_label(edge)) in path_permission_edges:
                continue
            remaining.append((source_label, display_edge_label(edge, target), typed_label(target)))

        if domain_trusts:
            print("\n" + paint("Domain trusts", "1", "36"))
            for local_domain, partner, direction, trust_type, attributes in sorted(
                domain_trusts, key=lambda item: (item[0].casefold(), item[1].casefold())
            ):
                details = [value for value in (direction, trust_type, attributes) if value]
                relation = "↔" if direction.casefold() == "bidirectional" else "→"
                suffix = f" ({'; '.join(details)})" if details else ""
                print(f"  {paint(local_domain, '1', '36')} {relation} {paint(partner, '1', '36')}{suffix}")

        if adcs_paths or adcs_findings or pki_relationships:
            if adcs_paths:
                print_path_section("ADCS", adcs_paths)
            else:
                print("\n" + paint("ADCS", "1", "36"))
            if adcs_findings:
                print(f"  {paint('Findings', '1', '33')}")
            for finding in sorted(adcs_findings.values(), key=lambda item: item["name"].casefold()):
                title = finding["name"]
                if finding["esc"] and not title.upper().startswith(finding["esc"]):
                    title = f"{finding['esc']} · {title}"
                print(f"    {paint(title, '1', '31') if finding['esc'] else paint(title, '1')}")
                for principal in sorted(finding["principals"], key=str.casefold):
                    principal_label = "Can enroll" if finding["esc"] == "ESC13" else "Principal"
                    print(f"      {principal_label}: {principal}")
                for group in sorted(finding["linked_groups"], key=str.casefold):
                    print(f"      Linked group: {group}")
            if pki_relationships:
                print(f"  {paint('Relationships', '1', '33')}")
                for kind, source_name, target_name in sorted(pki_relationships):
                    relation = {
                        "enterprise_ca_for": "Enterprise CA for",
                        "root_ca_for": "Root CA for",
                        "adcs_policy_link": "Issuance policy",
                        "adcs_template_link": "Uses template",
                    }.get(kind, kind)
                    print(f"    {relation}: {source_name} → {target_name}")

        if gpo_links:
            print("\n" + paint("GPO links", "1", "36"))
            for source_name, target_name in sorted(gpo_links, key=lambda item: (item[0].casefold(), item[1].casefold())):
                print(f"  {target_name}")
                print(f"    Linked from: {source_name}")

        if remaining:
            print("\n" + paint("Other graph findings and direct rights", "1", "36"))
            ranked_direct = sorted(set(remaining), key=path_priority)
            direct_limit = ranked_direct[:limit] if limit else ranked_direct
            by_target: dict[str, list[tuple[str, str]]] = {}
            for source, permission, target in direct_limit:
                by_target.setdefault(target, []).append((source, permission))
            for target, principals in sorted(by_target.items(), key=lambda item: item[0].casefold()):
                print(f"  {paint(target, '1')}")
                for source, permission in sorted(principals, key=lambda item: (item[0].casefold(), item[1].casefold())):
                    styled_permission = permission_color(permission.ljust(24))
                    print(f"    {styled_permission} {source}")
            if limit and len(ranked_direct) > limit:
                print(f"  ... {len(ranked_direct) - limit} more direct relationships omitted; increase --limit to show more")
    return 0


def analyze_graph_files(paths: list[str], from_user: str | None, limit: int, color_mode: str = "auto") -> int:
    """Render the report with domain context and high-priority findings first."""
    output = io.StringIO()
    with redirect_stdout(output):
        result = _render_analysis_report(paths, from_user, limit, color_mode)

    section_order = {
        "Domain overview": 10,
        "Domain Admins": 20,
        "Domain trusts": 30,
        "Effective permission paths": 40,
        "Kerberos roasting": 50,
        "Delegations": 60,
        "ADCS": 70,
        "GPO links": 80,
        "Other visible group memberships": 90,
        "Other graph findings and direct rights": 100,
        "Objects with adminCount=1": 110,
        "Object descriptions": 120,
    }
    ansi = re.compile(r"\x1b\[[0-9;]*m")
    chunks: list[tuple[str | None, str]] = []
    current_title: str | None = None
    current_lines: list[str] = []
    for line in output.getvalue().splitlines(keepends=True):
        plain = ansi.sub("", line).strip()
        if plain in section_order:
            if current_lines:
                chunks.append((current_title, "".join(current_lines)))
            current_title = plain
            current_lines = [line]
        else:
            current_lines.append(line)
    if current_lines:
        chunks.append((current_title, "".join(current_lines)))

    preamble = "".join(chunk for title, chunk in chunks if title is None).rstrip()
    sections = [(title, chunk) for title, chunk in chunks if title is not None]
    sections.sort(key=lambda item: section_order[item[0]])
    report = "\n\n".join(chunk.strip("\n") for _title, chunk in sections)
    print(f"{preamble}\n\n{report}" if report else preamble)
    return result
