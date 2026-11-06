"""Shared LDAP value and object helpers."""
from __future__ import annotations

import base64
import json
import re
from typing import Any


WELL_KNOWN_SID_NAMES = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-4": "Owner Rights",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicator",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}


def trustee_display_name(value: Any) -> str:
    """Replace only unresolved well-known SIDs with their standard names."""
    text = scalar(value).strip()
    return WELL_KNOWN_SID_NAMES.get(text.upper(), text)


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
    if "trusteddomain" in normalized:
        return "trusted_domain"
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
