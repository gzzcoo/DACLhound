"""DACLhound-owned ADWS transport, entry decoding, and schema GUID resolution."""
from __future__ import annotations

import base64
import binascii
import sys
import uuid
from typing import Any
from xml.etree import ElementTree as ET

from .acl import parse_security_descriptor
from ._protocol import ADWSConnect, NAMESPACES, NTLMAuth
from ._protocol.adws import KerberosAuth


def _status(marker: str, message: str, color: str) -> str:
    """Color ADWS progress markers when stderr is an interactive terminal."""
    if not sys.stderr.isatty():
        return f"[{marker}] {message}"
    return f"\x1b[{color}m[{marker}]\x1b[0m {message}"


def _values(item: ET.Element, name: str) -> list[str | bytes]:
    xpath = f".//addata:{name}/ad:value"
    found = item.findall(xpath, NAMESPACES)
    if not found:
        found = item.findall(f".//addata:{name.lower()}/ad:value", NAMESPACES)
    out: list[str | bytes] = []
    for element in found:
        if element.text is None:
            continue
        binary = (element.attrib.get(f"{{{NAMESPACES['xsi']}}}type", "").endswith("base64Binary")
                  or name.casefold() in {"objectsid", "objectguid", "sidhistory", "ntsecuritydescriptor",
                                        "msds-groupmsamembership", "cacertificate", "schemaidguid",
                                        "attributesecurityguid"})
        if binary:
            try:
                out.append(base64.b64decode(element.text, validate=True))
                continue
            except (binascii.Error, ValueError):
                pass
        out.append(element.text)
    return out


def _sid(raw: bytes) -> str:
    from impacket.ldap.ldaptypes import LDAP_SID
    return LDAP_SID(data=raw).formatCanonical()


def _guid(raw: bytes | str) -> str:
    if isinstance(raw, bytes) and len(raw) == 16:
        return str(uuid.UUID(bytes_le=raw)).upper()
    return str(raw).upper()


def _entry(item: ET.Element, attributes: list[str], guid_names: dict[str, str]) -> dict[str, Any]:
    entry: dict[str, Any] = {}
    for name in attributes:
        values = _values(item, name)
        if not values:
            continue
        if name.casefold() == "objectsid":
            values = [_sid(x) if isinstance(x, bytes) else x for x in values]
        elif name.casefold() == "objectguid":
            values = [_guid(x) if isinstance(x, bytes) else x for x in values]
        elif name.casefold() == "ntsecuritydescriptor":
            values = [parse_security_descriptor(x, guid_names) if isinstance(x, bytes) else {} for x in values]
        elif name.casefold() in {"msds-groupmsamembership", "msds-allowedtoactonbehalfofotheridentity"}:
            values = [parse_security_descriptor(x, guid_names) if isinstance(x, bytes) else {} for x in values]
        elif name.casefold() == "sidhistory":
            values = [_sid(x) if isinstance(x, bytes) else x for x in values]
        else:
            values = [base64.b64encode(x).decode("ascii") if isinstance(x, bytes) else x for x in values]
        entry[name] = values[0] if len(values) == 1 else values
    uac = entry.get("userAccountControl")
    if isinstance(uac, str) and uac.isdecimal():
        from ._protocol.adws import AccountPropertyFlag
        numeric = int(uac)
        entry["userAccountControl"] = [flag.name for flag in AccountPropertyFlag if numeric & int(flag)]
    for attr_name, mapping in (
        ("trustDirection", {0: "DISABLED", 1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"}),
        ("trustType", {1: "DOWNLEVEL", 2: "UPLEVEL", 3: "MIT"}),
    ):
        value = entry.get(attr_name)
        if isinstance(value, str) and value.isdecimal() and int(value) in mapping:
            entry[attr_name] = mapping[int(value)]
    trust_attributes = entry.get("trustAttributes")
    if isinstance(trust_attributes, str) and trust_attributes.isdecimal():
        flags = int(trust_attributes)
        trust_names = ((0x1, "NON_TRANSITIVE"), (0x2, "UPLEVEL_ONLY"),
                       (0x4, "QUARANTINED_DOMAIN"), (0x8, "FOREST_TRANSITIVE"),
                       (0x10, "CROSS_ORGANIZATION"), (0x20, "WITHIN_FOREST"),
                       (0x40, "TREAT_AS_EXTERNAL"), (0x80, "USES_RC4"),
                       (0x200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"), (0x400, "PIM_TRUST"))
        entry["trustAttributes"] = [name for bit, name in trust_names if flags & bit]
    # objectClass is multi-valued and classifiers need its complete chain.
    object_classes = _values(item, "objectClass")
    if object_classes:
        entry["objectClass"] = [str(x) for x in object_classes]
    return entry


class ADWSCollector:
    """Collect the same raw-entry shape as the LDAP provider using ADWS directly."""

    def __init__(self, host: str, domain: str, username: str, password: str | None,
                 hashes: str | None = None, timeout: int = 180, dc_ip: str | None = None,
                 kerberos: bool = False, kerberos_ticket: str | None = None,
                 kerberos_ccache: bytes | None = None, kdc_host: str | None = None):
        self.host = host
        self.domain = domain
        self.username = username
        self.auth = (KerberosAuth(ccache_path=kerberos_ticket, ccache_data=kerberos_ccache,
                                  kdc_host=kdc_host)
                     if kerberos else NTLMAuth(password=password, hashes=hashes))
        self.timeout = timeout
        self.dc_ip = dc_ip
        self.rootdse: dict[str, Any] = {}
        self.guid_names: dict[str, str] = {}

    def _client(self) -> ADWSConnect:
        return ADWSConnect.pull_client(self.host, self.domain, self.username, self.auth,
                                       connect_host=self.dc_ip, timeout=self.timeout)

    @staticmethod
    def _close(client: ADWSConnect | None) -> None:
        if client is not None:
            try:
                client._nmf._sock.close()
            except Exception:
                pass

    def _search(self, client: ADWSConnect, base: str, ldap_filter: str,
                attributes: list[str]) -> list[ET.Element]:
        result = client.pull(query=ldap_filter, attributes=attributes,
                             base_object_dn_for_soap=base)
        if result is None:
            raise RuntimeError(f"ADWS returned no enumeration result for {base} with filter {ldap_filter}; check the ADWS fault above")
        return list(result)

    def _resolve_schema_guids(self) -> None:
        schema_dn = str(self.rootdse.get("schemaNamingContext") or "")
        config_dn = str(self.rootdse.get("configurationNamingContext") or "")
        if schema_dn:
            client = None
            try:
                client = self._client()
                attrs = ["schemaIDGUID", "lDAPDisplayName"]
                for schema_class in ("attributeSchema", "classSchema"):
                    for item in self._search(client, schema_dn, f"(objectClass={schema_class})", attrs):
                        values = _values(item, "schemaIDGUID")
                        labels = _values(item, "lDAPDisplayName")
                        if values and labels and isinstance(values[0], bytes):
                            self.guid_names[_guid(values[0])] = str(labels[0])
            except Exception as exc:
                print(f"[!] ADWS schema attribute GUID lookup warning: {exc}", file=sys.stderr)
            finally:
                self._close(client)
        if config_dn:
            client = None
            try:
                client = self._client()
                base = f"CN=Extended-Rights,{config_dn}"
                attrs = ["rightsGuid", "displayName"]
                for item in self._search(client, base, "(objectClass=controlAccessRight)", attrs):
                    values = _values(item, "rightsGuid")
                    labels = _values(item, "displayName")
                    if values and labels:
                        self.guid_names[_guid(values[0])] = str(labels[0])
            except Exception as exc:
                print(f"[!] ADWS extended-right GUID lookup warning: {exc}", file=sys.stderr)
            finally:
                self._close(client)

    def collect(self, requested: set[str], type_map: dict[str, tuple[str, str]],
                attrs: str, include_adcs: bool = True) -> list[dict[str, Any]]:
        client = self._client()
        try:
            self.rootdse = client.get_rootdse_contexts(self.host, client._nmf) or {}
        finally:
            self._close(client)
        base_dn = str(self.rootdse.get("defaultNamingContext") or "")
        if not base_dn:
            base_dn = ",".join(f"DC={part}" for part in self.domain.rstrip(".").split(".") if part)
            if not base_dn:
                raise RuntimeError("ADWS RootDSE omitted defaultNamingContext and -d cannot be converted to a domain DN")
            self.rootdse["defaultNamingContext"] = base_dn
        root_dn = str(self.rootdse.get("rootDomainNamingContext") or base_dn)
        self.rootdse["rootDomainNamingContext"] = root_dn
        self.rootdse["configurationNamingContext"] = (
            self.rootdse.get("configurationNamingContext") or f"CN=Configuration,{root_dn}")
        self.rootdse["schemaNamingContext"] = (
            self.rootdse.get("schemaNamingContext") or f"CN=Schema,CN=Configuration,{root_dn}")
        self._resolve_schema_guids()
        attributes = [part.strip() for part in attrs.split(",") if part.strip()]
        entries: list[dict[str, Any]] = []
        client = self._client()
        try:
            for kind in sorted(requested):
                _, ldap_filter = type_map[kind]
                base = (f"CN=Sites,{self.rootdse['configurationNamingContext']}"
                        if kind == "sites" else base_dn)
                print(_status("*", f"Collecting {kind} through ADWS from {self.host}", "1;34"), file=sys.stderr)
                try:
                    for item in self._search(client, base, ldap_filter, attributes):
                        entries.append(_entry(item, attributes, self.guid_names))
                except Exception as exc:
                    if kind in {"sites", "foreign-security-principals"} and "no enumeration result" in str(exc).casefold():
                        print(f"[i] No {kind.replace('-', ' ')} found; continuing", file=sys.stderr)
                        continue
                    raise
            if include_adcs:
                self._collect_adcs(client, entries)
        finally:
            self._close(client)
        return entries

    def _collect_adcs(self, client: ADWSConnect, entries: list[dict[str, Any]]) -> None:
        config_dn = str(self.rootdse.get("configurationNamingContext") or "")
        if not config_dn:
            print("[!] ADWS RootDSE omitted configurationNamingContext; skipping ADCS", file=sys.stderr)
            return
        attrs = ["distinguishedName", "objectClass", "objectSid", "cn", "name", "displayName",
                 "nTSecurityDescriptor", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag",
                 "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "msPKI-RA-Application-Policies",
                 "msPKI-Template-Schema-Version", "msPKI-Certificate-Application-Policy",
                 "msPKI-Certificate-Policy", "msPKI-RA-Policies", "msPKI-Private-Key-Flag",
                 "msPKI-Cert-Template-OID", "msPKI-Template-Minor-Revision", "msDS-OIDToGroupLink",
                 "certificateTemplates", "dNSHostName", "cACertificate", "flags",
                 "altSecurityIdentities"]
        queries = [
            (config_dn, "(objectClass=pKICertificateTemplate)", "template"),
            (config_dn, "(objectClass=pKIEnrollmentService)", "ca"),
            (f"CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_dn}",
             "(objectClass=certificationAuthority)", "rootca"),
            (config_dn, "(objectClass=msPKI-Enterprise-Oid)", "oid"),
            (f"CN=Public Key Services,CN=Services,{config_dn}", "(objectClass=container)", "pki_object"),
        ]
        template_count = 0
        template_sd_count = 0
        for base, query, kind in queries:
            try:
                for item in self._search(client, base, query, attrs):
                    entry = _entry(item, attrs, self.guid_names)
                    entry["__daclgraph_adcs_kind"] = kind
                    entries.append(entry)
                    if kind == "template":
                        template_count += 1
                        descriptor = entry.get("nTSecurityDescriptor")
                        if isinstance(descriptor, dict) and "ACL" in descriptor:
                            template_sd_count += 1
            except Exception as exc:
                print(f"[!] ADWS ADCS {kind} collection warning: {exc}", file=sys.stderr)
        if template_count and template_sd_count == 0:
            print("[!] ADWS returned certificate templates without nTSecurityDescriptor; template Enroll ACLs and template DACL findings are unavailable.", file=sys.stderr)
        elif template_sd_count < template_count:
            print(f"[!] ADWS returned security descriptors for {template_sd_count}/{template_count} certificate templates; Enroll ACL results may be incomplete.", file=sys.stderr)
        ntauth_dn = f"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{config_dn}"
        try:
            for item in self._search(client, ntauth_dn, "(objectClass=*)",
                                     ["distinguishedName", "cACertificate"]):
                entry = _entry(item, ["distinguishedName", "cACertificate"], self.guid_names)
                entry["__daclgraph_adcs_kind"] = "ntauth"
                entries.append(entry)
        except Exception as exc:
            print(f"[!] ADWS ADCS NTAuth collection warning: {exc}", file=sys.stderr)
