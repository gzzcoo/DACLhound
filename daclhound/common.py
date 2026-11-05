"""Shared LDAP value and object helpers."""
from __future__ import annotations

import base64
import json
import re
from typing import Any


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
