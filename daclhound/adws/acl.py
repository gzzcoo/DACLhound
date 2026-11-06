"""Convert AD security descriptors returned by ADWS to DACLhound's raw ACL shape."""
from __future__ import annotations

import uuid
from typing import Any

from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR


_RIGHTS = (
    (0x10000000, "GENERIC_ALL"), (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"), (0x20000000, "GENERIC_EXECUTE"),
    (0x02000000, "MAXIMUM_ALLOWED"), (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x00100000, "SYNCHRONIZE"),
    (0x00080000, "WRITE_OWNER"), (0x00040000, "WRITE_DACL"),
    (0x00020000, "READ_CONTROL"), (0x00010000, "DELETE"),
    (0x00000100, "CONTROL_ACCESS"), (0x00000080, "LIST_OBJECT"),
    (0x00000040, "DELETE_TREE"), (0x00000020, "WRITE_PROP"),
    (0x00000010, "READ_PROP"), (0x00000008, "WRITE_VALIDATED"),
    (0x00000004, "LIST_CHILD"), (0x00000002, "DELETE_CHILD"),
    (0x00000001, "CREATE_CHILD"),
)


def _sid(value: Any) -> str:
    if not value:
        return ""
    try:
        return value.formatCanonical()
    except Exception:
        return str(value)


def _guid(value: Any) -> str:
    if not value:
        return ""
    try:
        raw = value.getData() if hasattr(value, "getData") else bytes(value)
        return str(uuid.UUID(bytes_le=raw)).upper()
    except Exception:
        return str(value)


def _mask_rights(mask: int, object_scoped: bool = False) -> str:
    # AD maps the four generic high bits to directory-service-specific masks.
    # Directory ACLs stored in AD usually contain the mapped mask, not the
    # original generic bit. Keep this mapping separate from ordinary rights:
    # ObjectType-scoped ACEs must remain property/extended-right permissions.
    generic_all = 0x10000000
    generic_write = 0x40000000
    generic_read = 0x80000000
    generic_execute = 0x20000000
    mapped_all = 0x000F01FF
    mapped_write = 0x00020028
    mapped_read = 0x00020094
    mapped_execute = 0x00020004

    rights: list[str] = []
    original = mask & 0xFFFFFFFF
    remaining = original

    if original & generic_all:
        rights.append("GENERIC_ALL")
        remaining &= ~generic_all
    elif original & mapped_all == mapped_all:
        # GENERIC_ALL subsumes the read/write/execute mappings and all AD
        # object rights, so recognize it before testing the smaller masks.
        rights.append("GENERIC_ALL")
        remaining &= ~mapped_all
    else:
        # Expanded masks lose their original generic-bit boundaries when AD
        # stores them. Infer a generic label only when the complete ACE mask is
        # an exact mapped right, or when all bits of GENERIC_WRITE/READ are
        # present. These labels describe effective rights; retain additional
        # bits separately. GENERIC_EXECUTE is only inferred from an exact mask
        # because its mapping is a subset of ordinary read/list permissions.
        if original & generic_write:
            rights.append("GENERIC_WRITE")
            remaining &= ~generic_write
        if original & generic_read:
            rights.append("GENERIC_READ")
            remaining &= ~generic_read
        if original & generic_execute:
            rights.append("GENERIC_EXECUTE")
            remaining &= ~generic_execute

        if not object_scoped:
            for mapped_mask, label in ((mapped_write, "GENERIC_WRITE"),
                                       (mapped_read, "GENERIC_READ")):
                if original & mapped_mask == mapped_mask:
                    rights.append(label)
                    remaining &= ~mapped_mask

            expanded_mappings = (
                (mapped_execute, ("GENERIC_EXECUTE",)),
            )
            for mapped_mask, labels in expanded_mappings:
                if original == mapped_mask and not rights:
                    rights.extend(labels)
                    remaining = 0
                    break

    rights.extend(name for bit, name in _RIGHTS if remaining & bit)
    recognized = 0
    for bit, _name in _RIGHTS:
        recognized |= bit
    unknown_bits = remaining & ~recognized
    if unknown_bits:
        rights.append(f"UNKNOWN_0x{unknown_bits:08X}")
    return "|".join(dict.fromkeys(rights)) or (f"0x{original:08X}" if original else "NO_ACCESS")


def parse_security_descriptor(raw: bytes, guid_names: dict[str, str] | None = None) -> dict[str, Any]:
    """Parse raw nTSecurityDescriptor bytes while retaining property GUID scopes."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        return {}
    sd = SR_SECURITY_DESCRIPTOR(data=bytes(raw))
    names = {k.upper(): v for k, v in (guid_names or {}).items()}
    dacl = sd["Dacl"]
    result: dict[str, Any] = {
        "Owner": _sid(sd["OwnerSid"]),
        "Control": f"0x{int(sd['Control']):04X}",
        "ACL": [],
    }
    if not dacl:
        return result
    for ace in dacl.aces:
        ace_type = int(ace["AceType"])
        body = ace["Ace"]
        mask = int(body["Mask"]["Mask"])
        object_guid = ""
        inherited_guid = ""
        object_scoped = False
        if "ObjectType" in body.fields and body["ObjectType"]:
            object_guid = _guid(body["ObjectType"])
        if "Flags" in body.fields:
            object_scoped = bool(int(body["Flags"]) & 0x01)
        if "InheritedObjectType" in body.fields and body["InheritedObjectType"]:
            inherited_guid = _guid(body["InheritedObjectType"])
        flags = int(ace["AceFlags"])
        flag_names = []
        for bit, label in ((0x01, "OBJECT_INHERIT"), (0x02, "CONTAINER_INHERIT"),
                           (0x04, "NO_PROPAGATE"), (0x08, "INHERIT_ONLY"),
                           (0x10, "INHERITED")):
            if flags & bit:
                flag_names.append(label)
        trustee = _sid(body["Sid"]) if "Sid" in body.fields else ""
        ace_name = str(ace["TypeName"] if "TypeName" in ace.fields else "")
        if "DENIED" in ace_name:
            ace_kind = "ACCESS_DENIED"
        elif "ALLOWED" in ace_name:
            ace_kind = "ACCESS_ALLOWED"
        else:
            ace_kind = ace_name.upper() or f"ACE_{ace_type:02X}"
        result["ACL"].append({
            "Trustee": trustee,
            "Type": ace_kind,
            "Right": _mask_rights(mask, object_scoped),
            "ObjectType": names.get(object_guid, object_guid),
            "ObjectTypeGuid": object_guid,
            "InheritedObjectType": names.get(inherited_guid, inherited_guid),
            "Flags": "|".join(flag_names),
            "Mask": f"0x{mask:08X}",
        })
    return result
