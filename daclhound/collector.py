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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .adcs import adcs_assessment, add_adcs_findings
from .common import (WELL_KNOWN_SID_NAMES, attr, canonical_sid, classify, int_attr, object_types, scalar,
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
    """Request a password-based TGT with Impacket, retrying on KDC clock skew.

    Impacket first asks the KDC for the account's pre-authentication salt.
    Keep this path so AES accounts with non-default salts continue to work.
    The retry applies the KDC-provided time offset only inside Impacket's
    Kerberos request code; it never changes the operating-system clock.
    """
    from types import SimpleNamespace

    from impacket.krb5 import constants, kerberosv5
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
    from impacket.krb5.types import Principal

    principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    def get_tgt() -> tuple[bytes, Any, Any, Any]:
        return getKerberosTGT(
            clientName=principal,
            password=password,
            domain=domain.upper(),
            lmhash=b"",
            nthash=b"",
            aesKey=None,
            kdcHost=kdc_host,
        )

    try:
        tgt, _cipher, old_session_key, session_key = get_tgt()
    except KerberosError as exc:
        if exc.getErrorCode() != constants.ErrorCodes.KRB_AP_ERR_SKEW.value:
            raise

        packet = exc.getErrorPacket()
        try:
            server_time_raw = packet["stime"].asOctets().decode("ascii")
            server_time = dt.datetime.strptime(server_time_raw, "%Y%m%d%H%M%SZ").replace(
                tzinfo=dt.timezone.utc
            )
        except (KeyError, AttributeError, UnicodeDecodeError, ValueError) as parse_exc:
            raise RuntimeError(
                "KDC reported Kerberos clock skew but did not provide a usable server time"
            ) from parse_exc

        skew = server_time - dt.datetime.now(dt.timezone.utc)
        print(
            f"[!] Kerberos clock skew detected. Applying in-memory offset {skew}; retrying.",
            file=sys.stderr,
        )

        real_datetime = dt.datetime

        class OffsetDateTime(real_datetime):
            @classmethod
            def now(cls, tz: dt.tzinfo | None = None) -> dt.datetime:
                return real_datetime.now(tz) + skew

        original_datetime_module = kerberosv5.datetime
        kerberosv5.datetime = SimpleNamespace(
            datetime=OffsetDateTime,
            timezone=dt.timezone,
            timedelta=dt.timedelta,
        )
        try:
            tgt, _cipher, old_session_key, session_key = get_tgt()
        finally:
            kerberosv5.datetime = original_datetime_module

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


def _status(marker: str, message: str, color: str) -> str:
    """Color collector progress markers when stderr is an interactive terminal."""
    if not sys.stderr.isatty():
        return f"[{marker}] {message}"
    return f"\x1b[{color}m[{marker}]\x1b[0m {message}"


def json_value(value: Any) -> Any:
    """Match bloodyAD's JSON conversion for values returned by its search renderer."""
    if isinstance(value, dict):
        result = {}
        for key, member in value.items():
            if key.casefold() in {"tokengroups", "tokengroupsnogcaacceptable"}:
                values = member if isinstance(member, (list, tuple, set)) else [member]
                result[key] = [base64.b64encode(value).decode("ascii") if isinstance(value, bytes)
                               else json_value(value) for value in values]
            else:
                result[key] = json_value(member)
        return result
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
    sccm_report: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    patch_badldap_rfc4515_compat()
    from bloodyAD.cli_modules.get import search as bloodyad_search
    from bloodyAD.exceptions import NoResultError
    from bloodyAD.network.config import Config, ConnectionHandler
    from bloodyAD.network.ldap import Scope

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
            print(_status("*", f"Collecting {label} from {host}", "1;34"), file=sys.stderr)
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
                    print(_status("*", f"Collecting ADCS {label} from {host}", "1;34"), file=sys.stderr)
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
        # tokenGroups is computed by AD and only works in BASE scope. Query it
        # per non-default user instead of including it in the broad subtree
        # searches above (which fail with ERROR_DS_NON_BASE_SEARCH).
        ldap = await conn.getLdap()
        if sccm_report is not None:
            from .sccm import discover_sccm

            sccm_report.update(await discover_sccm(ldap))
        token_group_failures = 0
        for entry in entries:
            if classify(entry) != "user":
                continue
            sid = canonical_sid(attr(entry, "objectSid"))
            account_name = scalar(attr(entry, "sAMAccountName")).strip().casefold()
            if account_name == "administrator" or sid.endswith("-500"):
                continue
            dn = scalar(attr(entry, "distinguishedName")).strip()
            if not dn:
                continue
            token_sids: list[str] = []
            base_query_succeeded = False
            for token_attribute in ("tokenGroups", "tokenGroupsNoGCAcceptable"):
                try:
                    async for token_entry in ldap.bloodysearch(
                        dn, "(objectClass=*)", search_scope=Scope.BASE,
                        attr=[token_attribute], control_flag=0,
                    ):
                        base_query_succeeded = True
                        values = attr(token_entry, token_attribute, []) or []
                        if not isinstance(values, list):
                            values = [values]
                        token_sids = [sid_value for value in values
                                      if (sid_value := canonical_sid(value))]
                    if token_sids:
                        break
                except Exception:
                    continue
            if not base_query_succeeded:
                token_group_failures += 1
            entry["daclgraphTokenGroupSids"] = token_sids
        if token_group_failures:
            print(f"[!] Could not read effective group memberships for {token_group_failures} user(s); continuing",
                  file=sys.stderr)
    finally:
        await conn.closeLdap()
    return entries


def collect_host_service_checks(
    entries: list[dict[str, Any]], *, username: str, domain: str,
    password: str = "", hashes: str = "", aes_key: str = "",
    kerberos: bool = False, ccache: str | None = None, kdc_host: str = "",
    dns_server: str | None = None,
    timeout: int = 3, workers: int = 8,
) -> None:
    """Collect host security checks for computers and LDAP policy for DCs.

    SMB signing is read from the unauthenticated protocol negotiation. WebClient
    is identified by opening its DAV RPC named pipe in IPC$, matching the
    protocol-level check used by common SMB collectors without invoking one.
    LDAP policy values are read from the DC registry over Remote Registry RPC.
    """
    computers: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if classify(entry) != "computer":
            continue
        hostname = scalar(attr(entry, "dNSHostName")).strip().rstrip(".")
        if hostname:
            computers.setdefault(hostname.casefold(), []).append(entry)
    if not computers:
        print("[i] Host service checks skipped: no computer DNS names were collected", file=sys.stderr)
        return
    try:
        from impacket import nt_errors
        from impacket.dcerpc.v5 import rrp, transport
        from impacket.smbconnection import SMBConnection, SessionError
        from impacket.smb3structs import (
            FILE_READ_DATA, SMB2_DIALECT_30, SMB2_NEGOTIATE_SIGNING_REQUIRED,
        )
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "--host-checks requires Impacket in the active Python environment; "
            "run DACLhound.py with .release-venv/bin/python "
            f"(missing module: {exc.name})"
        ) from exc

    old_ccache = os.environ.get("KRB5CCNAME")
    if kerberos and ccache:
        os.environ["KRB5CCNAME"] = ccache
    lmhash, nthash = "", ""
    if hashes:
        if ":" in hashes:
            lmhash, nthash = hashes.split(":", 1)
        else:
            nthash = hashes

    def is_domain_controller(host_entries: list[dict[str, Any]]) -> bool:
        for entry in host_entries:
            flags = attr(entry, "userAccountControl", []) or []
            flags = flags if isinstance(flags, list) else [flags]
            if (scalar(attr(entry, "primaryGroupID")).strip() == "516"
                    or any(scalar(flag).strip().upper() == "SERVER_TRUST_ACCOUNT" for flag in flags)
                    or re.search(r"(?:^|,)OU=Domain Controllers(?:,|$)",
                                 scalar(entry.get("distinguishedName")), re.I)):
                return True
        return False

    def read_ldap_policy(connection: Any, host: str, remote_host: str) -> dict[str, int | None]:
        result: dict[str, int | None] = {
            "ldapServerIntegrity": None,
            "ldapServerEnforceIntegrity": None,
            "ldapEnforceChannelBinding": None,
        }
        dce = None
        root = key = None
        try:
            rpc = transport.SMBTransport(remoteName=host, remoteHost=remote_host,
                                         filename=r"\winreg", smb_connection=connection)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            root = rrp.hOpenLocalMachine(dce, samDesired=rrp.KEY_READ)["phKey"]
            key = rrp.hBaseRegOpenKey(
                dce, root, r"SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
                samDesired=rrp.KEY_READ,
            )["phkResult"]
            for name, field in (
                ("LDAPServerIntegrity", "ldapServerIntegrity"),
                ("LDAPServerEnforceIntegrity", "ldapServerEnforceIntegrity"),
                ("LdapEnforceChannelBinding", "ldapEnforceChannelBinding"),
            ):
                try:
                    value_type, value = rrp.hBaseRegQueryValue(dce, key, name)
                    if value_type == rrp.REG_DWORD:
                        result[field] = int(value)
                except Exception:
                    # Missing/blocked values remain unknown; do not infer policy defaults.
                    continue
        finally:
            if dce is not None:
                for handle in (key, root):
                    if handle is not None:
                        try:
                            rrp.hBaseRegCloseKey(dce, handle)
                        except Exception:
                            pass
                try:
                    dce.disconnect()
                except Exception:
                    pass
        return result

    def check(host: str) -> tuple[str, bool | None, bool | None, dict[str, int | None] | None, str | None]:
        connection = None
        signing: bool | None = None
        webclient: bool | None = None
        ldap_policy: dict[str, int | None] | None = None
        authenticated = False
        problem = None
        try:
            remote_host = host
            if dns_server:
                try:
                    import dns.resolver
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [dns_server]
                    resolver.timeout = timeout
                    resolver.lifetime = timeout
                    address = None
                    for record_type in ("A", "AAAA"):
                        try:
                            answer = resolver.resolve(host, record_type)
                            address = str(answer[0])
                            break
                        except Exception:
                            continue
                    if address:
                        remote_host = address
                    else:
                        remote_host = socket.getaddrinfo(host, 445, type=socket.SOCK_STREAM)[0][4][0]
                except ImportError:
                    remote_host = socket.getaddrinfo(host, 445, type=socket.SOCK_STREAM)[0][4][0]
            connection = SMBConnection(remoteName=host, remoteHost=remote_host, timeout=timeout)
            dialect = connection.getDialect()
            if isinstance(dialect, int) and dialect >= SMB2_DIALECT_30:
                security_mode = connection.getSMBServer()._Connection.get("ServerSecurityMode")
                signing = (bool(security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED)
                           if security_mode is not None else None)
            else:
                signing = bool(connection.isSigningRequired())
            try:
                if kerberos:
                    connection.kerberosLogin(username, password, domain, lmhash, nthash,
                                             aes_key, kdc_host or None)
                else:
                    connection.login(username, password, domain, lmhash, nthash)
                authenticated = True
                tree_id = connection.connectTree("IPC$")
                file_id = connection.openFile(tree_id, "DAV RPC Service", desiredAccess=FILE_READ_DATA)
                connection.closeFile(tree_id, file_id)
                webclient = True
            except SessionError as exc:
                if exc.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                    webclient = False
                else:
                    problem = f"WebClient pipe check returned SMB status {exc.getErrorCode():#x}"
            except Exception as exc:
                problem = f"WebClient pipe check failed ({type(exc).__name__}: {exc})"
            if authenticated and is_domain_controller(computers[host.casefold()]):
                try:
                    ldap_policy = read_ldap_policy(connection, host, remote_host)
                except Exception as exc:
                    problem = (problem + "; " if problem else "") + (
                        f"LDAP policy check failed ({type(exc).__name__}: {exc})"
                    )
        except Exception as exc:
            problem = f"SMB probe failed ({type(exc).__name__}: {exc})"
        finally:
            if connection is not None:
                try:
                    connection.logoff()
                except Exception:
                    pass
        return host, signing, webclient, ldap_policy, problem

    print(_status("*", f"Checking SMB signing and WebClient on {len(computers)} computers; LDAP policy on domain controllers", "1;34"), file=sys.stderr)
    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(check, host): host for host in computers}
            for future in as_completed(futures):
                host, signing, webclient, ldap_policy, problem = future.result()
                for entry in computers[host.casefold()]:
                    entry["daclgraphSmbSigningRequired"] = signing
                    entry["daclgraphWebClientRunning"] = webclient
                    if ldap_policy is not None:
                        integrity = ldap_policy["ldapServerIntegrity"]
                        enforcement = ldap_policy["ldapServerEnforceIntegrity"]
                        entry["daclgraphLdapServerSigningRequired"] = (
                            True if enforcement == 1
                            else integrity == 2 if integrity in (0, 2)
                            else None
                        )
                        entry["daclgraphLdapServerIntegrity"] = integrity
                        entry["daclgraphLdapServerEnforceIntegrity"] = enforcement
                        entry["daclgraphLdapEnforceChannelBinding"] = ldap_policy["ldapEnforceChannelBinding"]
                if problem:
                    print(f"[i] {host}: {problem}", file=sys.stderr)
    finally:
        if kerberos and ccache:
            if old_ccache is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = old_ccache


def build_dataset(
    entries: list[dict[str, Any]], domain: str, selected: set[str],
    sccm_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nodes, edges = [], []
    sccm_by_host = {
        scalar(item.get("hostname")).casefold(): item
        for item in (sccm_report or {}).get("computers", [])
        if scalar(item.get("hostname"))
    }
    by_name: dict[str, str] = {}
    entries_by_node_id: dict[str, dict[str, Any]] = {}
    for entry in entries:
        kind = classify(entry)
        sid = canonical_sid(attr(entry, "objectSid"))
        # ForeignSecurityPrincipal is also used to materialize several Windows
        # well-known SIDs. Those are trustees, not foreign domain principals.
        if kind == "foreign_security_principal" and sid.upper() in WELL_KNOWN_SID_NAMES:
            continue
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
        uac_numeric = None
        for flag in uac:
            value = scalar(flag).strip()
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", value, re.IGNORECASE):
                uac_numeric = int(value, 16 if value.lower().startswith("0x") else 10)
                break
        uac_has = lambda flag, bit: flag in uac_flags or (uac_numeric is not None and bool(uac_numeric & bit))
        delegate_to = attr(entry, "msDS-AllowedToDelegateTo", []) or []
        if isinstance(delegate_to, str):
            delegate_to = [delegate_to]
        service_principal_names = attr(entry, "servicePrincipalName", []) or []
        if isinstance(service_principal_names, str):
            service_principal_names = [service_principal_names]
        service_principal_names = [scalar(value).strip() for value in service_principal_names
                                   if scalar(value).strip()]
        admin_count = scalar(attr(entry, "adminCount")).strip().casefold() in {"1", "true"}
        disabled = "ACCOUNTDISABLE" in uac_flags or uac_has("ACCOUNTDISABLE", 0x2)
        no_preauth = (bool({"DONT_REQ_PREAUTH", "DONT_REQUIRE_PREAUTH"} & uac_flags)
                      or uac_has("DONT_REQ_PREAUTH", 0x400000))
        members = entry.get("member", [])
        if kind == "group" and (sam or name).casefold() == "domain users":
            members = []
        token_groups = attr(entry, "daclgraphTokenGroupSids", []) or []
        if not isinstance(token_groups, list):
            token_groups = [token_groups]
        direct_token_groups = attr(entry, "tokenGroups", []) or []
        if not isinstance(direct_token_groups, list):
            direct_token_groups = [direct_token_groups]
        token_groups = [*token_groups, *direct_token_groups]
        token_groups_fallback = attr(entry, "tokenGroupsNoGCAcceptable", []) or []
        if not isinstance(token_groups, list):
            token_groups = [token_groups]
        if not isinstance(token_groups_fallback, list):
            token_groups_fallback = [token_groups_fallback]
        token_groups = [*token_groups, *token_groups_fallback]
        sccm_profile = sccm_by_host.get(scalar(attr(entry, "dNSHostName")).casefold())
        smb_signing_required = entry.get("daclgraphSmbSigningRequired")
        if not isinstance(smb_signing_required, bool):
            smb_signing_required = ((sccm_profile or {}).get("smb") or {}).get("signingRequired")
        nodes.append({"id": node_id, "name": name, "type": kind, "dn": dn,
                      "sid": scalar(entry.get("objectSid")), "owner": scalar(descriptor.get("Owner")),
                      "sidHistory": [sid for value in sid_history
                                     for sid in [canonical_sid(value)] if sid],
                      "control": scalar(descriptor.get("Control")),
                      "memberOf": entry.get("memberOf", []), "members": members,
                      "dNSHostName": scalar(attr(entry, "dNSHostName")),
                      "sccm": sccm_profile,
                      "primaryGroupID": scalar(entry.get("primaryGroupID")),
                      "tokenGroups": token_groups,
                      "samAccountName": sam, "displayName": display_name,
                      "groupType": int_attr(entry, "groupType"),
                      "description": scalar(attr(entry, "description")),
                      "scriptPath": scalar(attr(entry, "scriptPath")),
                      "operatingSystem": scalar(attr(entry, "operatingSystem")),
                      "operatingSystemVersion": scalar(attr(entry, "operatingSystemVersion")),
                      "smbSigningRequired": smb_signing_required,
                      "webClientRunning": entry.get("daclgraphWebClientRunning"),
                        "ldapServerSigningRequired": entry.get("daclgraphLdapServerSigningRequired"),
                        "ldapServerIntegrity": entry.get("daclgraphLdapServerIntegrity"),
                        "ldapServerEnforceIntegrity": entry.get("daclgraphLdapServerEnforceIntegrity"),
                        "ldapEnforceChannelBinding": entry.get("daclgraphLdapEnforceChannelBinding"),
                      "isGmsa": kind == "user" and "msds-groupmanagedserviceaccount" in {scalar(value).casefold() for value in (attr(entry, "objectClass", []) or []) if scalar(value)},
                      "homeDirectory": scalar(attr(entry, "homeDirectory")),
                      "whenCreated": scalar(attr(entry, "whenCreated")),
                      "pwdLastSet": scalar(attr(entry, "pwdLastSet")),
                      "lastLogon": scalar(attr(entry, "lastLogon")),
                      "lastLogonTimestamp": scalar(attr(entry, "lastLogonTimestamp")),
                      "gPLink": scalar(entry.get("gPLink")),
                      "gPOptions": scalar(entry.get("gPOptions")),
                      "gPCFileSysPath": scalar(entry.get("gPCFileSysPath")),
                      "gPCWQLFilter": scalar(entry.get("gPCWQLFilter")),
                      "versionNumber": scalar(entry.get("versionNumber")),
                      "userAccountControl": sorted(uac_flags),
                      "markedSensitive": uac_has("NOT_DELEGATED", 0x100000) if uac_present else None,
                      "passwordNotRequired": uac_has("PASSWD_NOTREQD", 0x20) if uac_present else None,
                      "passwordNeverExpires": uac_has("DONT_EXPIRE_PASSWORD", 0x10000) if uac_present else None,
                      "adminCount": admin_count,
                      "servicePrincipalNames": service_principal_names,
                      "asrepRoastable": kind == "user" and no_preauth and not disabled,
                      "kerberoastable": kind == "user" and bool(service_principal_names) and not disabled,
                      "enabled": not disabled if uac_present and kind in {"user", "computer"} else None,
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
        if group_name == "domain users":
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

    # tokenGroups is AD's transitive security-group view. Keep only memberships
    # that expose non-default users in high-impact administrator groups; adding
    # every token group would flood the graph with routine memberships.
    privileged_group_ids = {
        group["id"] for group in nodes
        if group.get("type") == "group"
        and (canonical_sid(group.get("sid")) == "S-1-5-32-544"
             or canonical_sid(group.get("sid")).endswith(("-512", "-519")))
    }
    for user in nodes:
        if user.get("type") != "user":
            continue
        sid = canonical_sid(user.get("sid"))
        sam = scalar(user.get("samAccountName") or user.get("name")).strip().casefold()
        if sam == "administrator" or sid.endswith("-500"):
            continue
        token_groups = user.get("tokenGroups") or []
        if not isinstance(token_groups, list):
            token_groups = [token_groups]
        for token_sid in token_groups:
            group_id = canonical_sid(token_sid)
            if group_id in privileged_group_ids:
                add_membership(user["id"], group_id)
    for node in nodes:
        node.pop("tokenGroups", None)

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
    if sccm_report is not None:
        # SCCM inventory is visual context, not an AD attack-path relationship.
        # Represent each discovered Configuration Manager site as its own node
        # and connect it only to computer objects already present in this graph.
        computers_by_host = {
            scalar(node.get("dNSHostName")).strip().rstrip(".").casefold(): node
            for node in nodes if node.get("type") == "computer" and node.get("dNSHostName")
        }
        sites_by_code: dict[str, dict[str, Any]] = {}
        sccm_nodes: dict[str, dict[str, Any]] = {}
        for site in sccm_report.get("sites", []):
            code = scalar(site.get("siteCode")).strip()
            site_name = scalar(site.get("name")).strip()
            identity = code or site_name or scalar(site.get("dn"))
            if not identity:
                continue
            normalized = identity.casefold()
            node_id = f"sccm-site::{domain.casefold()}::{re.sub(r'[^a-z0-9]+', '-', normalized).strip('-')}"
            node = {"id": node_id, "name": code or site_name or "Unknown Site",
                    "type": "sccm_site", "domain": domain, "dn": scalar(site.get("dn")),
                    "sccm": {"siteCode": code, "siteName": site_name,
                             "managementPoints": [], "potentialDistributionPoints": [],
                             "serverRoles": [],
                             "principalCount": len(sccm_report.get("principals", []))}}
            nodes.append(node)
            sccm_nodes[normalized] = node
            if code:
                sites_by_code[code.casefold()] = node

        def add_sccm_inventory_edge(site_node: dict[str, Any], host: str, role: str) -> None:
            computer = computers_by_host.get(host.strip().rstrip(".").casefold())
            if not computer:
                return
            if role == "Management Point":
                if computer["name"] not in site_node["sccm"]["managementPoints"]:
                    site_node["sccm"]["managementPoints"].append(computer["name"])
            elif role == "Potential PXE DP":
                if computer["name"] not in site_node["sccm"]["potentialDistributionPoints"]:
                    site_node["sccm"]["potentialDistributionPoints"].append(computer["name"])
            else:
                record = {"hostname": computer["name"], "role": role}
                if record not in site_node["sccm"]["serverRoles"]:
                    site_node["sccm"]["serverRoles"].append(record)
            edge = next((item for item in edges
                         if item.get("kind") == "sccm_inventory"
                         and item.get("source") == site_node["id"]
                         and item.get("target") == computer["id"]), None)
            if edge is None:
                edge = {"id": f"sccm-inventory::{site_node['id']}::{computer['id']}",
                        "kind": "sccm_inventory", "source": site_node["id"],
                        "target": computer["id"], "sourceName": site_node["name"],
                        "sourceType": "sccm_site", "targetName": computer["name"],
                        "targetType": "computer", "roles": [],
                        "isACL": False, "traversable": False}
                edges.append(edge)
            if role not in edge["roles"]:
                edge["roles"].append(role)
                edge["roles"].sort(key=str.casefold)
            edge["right"] = f"SCCM roles ({len(edge['roles'])})"
            edge["relationship"] = edge["right"]

        for point in sccm_report.get("managementPoints", []):
            site_node = sites_by_code.get(scalar(point.get("siteCode")).strip().casefold())
            if site_node:
                add_sccm_inventory_edge(site_node, scalar(point.get("hostname")), "Management Point")
        # LDAP's PXE connectionPoint evidence is not site-scoped. Only associate
        # it with a site when the domain has exactly one discovered site.
        discovered_sites = list(sccm_nodes.values())
        if len(discovered_sites) == 1:
            for point in sccm_report.get("potentialDistributionPoints", []):
                add_sccm_inventory_edge(discovered_sites[0], scalar(point.get("hostname")),
                                        "Potential PXE DP")
        for item in sccm_report.get("computers", []):
            smb = item.get("smb", {})
            tcp = item.get("tcpIndicators", {})
            roles = {scalar(role).strip().casefold().replace("_", "-")
                     for role in [*(item.get("ldapRoles") or []), *(smb.get("roles") or [])]}
            site_codes = {scalar(code).strip().casefold()
                          for code in [*(item.get("ldapSiteCodes") or []), *(smb.get("siteCodes") or [])]
                          if scalar(code).strip()}
            matched_sites = {sites_by_code[code]["id"]: sites_by_code[code]
                             for code in site_codes if code in sites_by_code}
            full_control_site_candidate = "system management full control" in roles
            if not matched_sites and len(discovered_sites) == 1 and (roles or full_control_site_candidate):
                matched_sites[discovered_sites[0]["id"]] = discovered_sites[0]
            state = scalar(item.get("siteServerConfiguration") or item.get("siteServerState")
                           or item.get("configuration") or smb.get("siteServerConfiguration")).strip().casefold()
            server_roles = []
            site_server_state = scalar(item.get("siteServerConfiguration") or item.get("siteServerState")
                                       or item.get("configuration") or smb.get("siteServerConfiguration"))
            inferred_site_server = site_server_state.casefold() in {"active", "passive"}
            if ("site-server" in roles or item.get("siteServer") is True
                    or full_control_site_candidate or inferred_site_server):
                smb_authenticated = smb.get("status") == "authenticated"
                state_label = ("Passive · inferred" if "passive" in state and "site-share" in scalar(item.get("siteServerDetection")).casefold() else
                               "Passive" if "passive" in state else
                               "Active" if "active" in state and "inactive" not in state else
                               "Active" if smb_authenticated and "site-server" in roles else
                               "Passive" if smb_authenticated and full_control_site_candidate else
                               "state unknown")
                server_roles.append(f"Site Server · {state_label}")
            if "sms-provider" in roles or item.get("smsProvider") is True:
                server_roles.append("SMS Provider")
            if "distribution-point" in roles:
                server_roles.append("Distribution Point")
            if "wsus" in roles or item.get("wsus") is True or tcp.get("wsus8530") or tcp.get("wsus8531"):
                server_roles.append("WSUS")
            if tcp.get("mssql1433") and roles:
                server_roles.append("MSSQL (1433)")
            for site_node in matched_sites.values():
                for role in server_roles:
                    add_sccm_inventory_edge(site_node, scalar(item.get("hostname")), role)

        # Model takeover routes as edges between the SCCM machine account and
        # the concrete service target. The service nodes are distinct from the
        # AD computer objects that host them.
        report_computers = sccm_report.get("computers", [])
        site_codes = {scalar(site.get("siteCode")).strip().casefold(): site
                      for site in sccm_report.get("sites", []) if scalar(site.get("siteCode")).strip()}

        def normalize_host(value: Any) -> str:
            return scalar(value).strip().rstrip(".").casefold()

        def report_computer(hostname: str) -> dict[str, Any] | None:
            wanted = normalize_host(hostname)
            exact = next((item for item in report_computers
                          if normalize_host(item.get("hostname")) == wanted), None)
            if exact or "." in wanted:
                return exact
            matches = [item for item in report_computers
                       if normalize_host(item.get("hostname")).split(".", 1)[0] == wanted]
            return matches[0] if len(matches) == 1 else None

        def graph_computer(hostname: str) -> dict[str, Any] | None:
            wanted = normalize_host(hostname)
            exact = computers_by_host.get(wanted)
            if exact or "." in wanted:
                return exact
            matches = [node for fqdn, node in computers_by_host.items()
                       if fqdn.split(".", 1)[0] == wanted]
            return matches[0] if len(matches) == 1 else None

        def item_site_codes(item: dict[str, Any]) -> set[str]:
            smb = item.get("smb") or {}
            return {normalize_host(value) for value in
                    [*(item.get("ldapSiteCodes") or []), *(smb.get("siteCodes") or [])] if normalize_host(value)}

        def sites_for(item: dict[str, Any], fallback_codes: list[str] | None = None) -> list[dict[str, Any]]:
            codes = {normalize_host(code) for code in (fallback_codes or []) if normalize_host(code)}
            codes.update(item_site_codes(item))
            matched = [site for code, site in site_codes.items() if code in codes]
            if not matched and len(site_codes) == 1:
                matched = [next(iter(site_codes.values()))]
            return matched

        def active_site_servers(site: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
            code = normalize_host(site.get("siteCode"))
            active = []
            for item in report_computers:
                smb = item.get("smb") or {}
                roles = {normalize_host(role).replace("_", "-")
                         for role in [*(item.get("ldapRoles") or []), *(smb.get("roles") or [])]}
                state = normalize_host(item.get("siteServerConfiguration") or smb.get("siteServerConfiguration"))
                is_active = state == "active" or (
                    state != "passive" and "site-server" in roles
                    and smb.get("status") == "authenticated"
                )
                item_codes = item_site_codes(item)
                if not is_active or (item_codes and code and code not in item_codes):
                    continue
                node = graph_computer(scalar(item.get("hostname")))
                if node:
                    active.append((item, node))
            return active

        def add_sccm_host_edge(service_node: dict[str, Any], host_node: dict[str, Any], role: str) -> None:
            edges.append({"id": f"sccm-host::{service_node['id']}::{host_node['id']}",
                          "kind": "sccm_host", "source": service_node["id"],
                          "target": host_node["id"], "sourceName": service_node["name"],
                          "sourceType": service_node["type"], "targetName": host_node["name"],
                          "targetType": "computer", "relationship": "Hosted on",
                          "role": role, "isACL": False, "traversable": False})

        def add_sccm_attack_edge(source: dict[str, Any], target: dict[str, Any], attack_type: str,
                                 requirements: list[str], evidence: list[str], *,
                                 status: str = "conditional", traversable: bool = True) -> None:
            edges.append({"id": f"sccm-attack::{attack_type}::{source['id']}::{target['id']}",
                          "kind": "sccm_attack", "attackType": attack_type,
                          "source": source["id"], "target": target["id"],
                          "sourceName": source["name"], "sourceType": source["type"],
                          "targetName": target["name"], "targetType": target["type"],
                          "requirements": requirements, "evidence": evidence,
                          "status": status, "isACL": False, "traversable": traversable})

        database_nodes: dict[tuple[str, str], dict[str, Any]] = {}
        for database in sccm_report.get("siteDatabases", []):
            hostname = scalar(database.get("hostname")).strip().rstrip(".")
            if not hostname:
                continue
            source_item = next((item for item in report_computers
                                if normalize_host(item.get("hostname")) == normalize_host(database.get("siteServer"))), None)
            target_item = report_computer(hostname)
            hostname = scalar((target_item or {}).get("hostname") or hostname).strip().rstrip(".")
            target_computer = graph_computer(hostname)
            for site in sites_for(source_item or {}, database.get("siteCodes")):
                site_code = scalar(site.get("siteCode")).strip()
                key = (site_code.casefold(), hostname.casefold())
                database_node = database_nodes.get(key)
                if database_node is None:
                    target_smb = (target_item or {}).get("smb") or {}
                    target_tcp = (target_item or {}).get("tcpIndicators") or {}
                    discovery = database.get("discovery", "SCCM profiling")
                    inferred_database = str(discovery).startswith("TCP/1433 fallback")
                    database_node = {
                        "id": f"sccm-database::{domain.casefold()}::{site_code.casefold()}::{hostname.casefold()}",
                        "name": f"{'Potential Site Database' if inferred_database else 'Site Database'} · {hostname}",
                        "type": "sccm_database", "domain": domain,
                        "sccm": {"role": "Potential Site Database", "siteCode": site_code,
                                 "hostname": hostname, "discovery": discovery,
                                 "mssqlReachable": target_tcp.get("mssql1433"),
                                 "smbSigningRequired": target_smb.get("signingRequired"),
                                 "smbStatus": target_smb.get("status", "not-profiled")},
                    }
                    nodes.append(database_node)
                    database_nodes[key] = database_node
                    target_site = sites_by_code.get(site_code.casefold())
                    if target_site:
                        target_site["sccm"].setdefault("siteDatabases", []).append(hostname)
                    if target_computer:
                        add_sccm_host_edge(database_node, target_computer, "MSSQL site database")
                for source_item_active, source_node in active_site_servers(site):
                    if normalize_host(hostname) == normalize_host(source_item_active.get("hostname")):
                        continue
                    requirements = [
                        "The primary MSSQL site database must run on a server separate from the Primary Site Server.",
                        "The Primary Site Server computer account must be a member of the site database server's local Administrators group.",
                        "The Primary Site Server must be coercible into authenticating to the relay.",
                    ]
                    primary_host = scalar(source_item_active.get("hostname") or database.get("siteServer")).strip().rstrip(".")
                    evidence = [
                        f"The Primary Site Server ({primary_host}) and potential MSSQL site database host ({hostname}) are different systems.",
                        (f"Potential site database candidate inferred from TCP/1433 and SCCM site association; Remote Registry query {database.get('registryStatus', 'unavailable')}."
                         if str(database.get("discovery", "")).startswith("TCP/1433 fallback")
                         else f"Remote Registry candidate on {database.get('siteServer')}: {database.get('discovery', 'SCCM profiling')}."),
                    ]
                    target_smb = (target_item or {}).get("smb") or {}
                    target_tcp = (target_item or {}).get("tcpIndicators") or {}
                    if (target_smb.get("signingRequired") is False
                            and target_smb.get("status") in {"authenticated", "authentication-failed"}):
                        add_sccm_attack_edge(
                            source_node, database_node, "CoerceAndRelayToSMB",
                            requirements + ["For the SMB route, SMB must be reachable on the database server and SMB signing must not be required."],
                            evidence + ["SMB signing is not required on the target."])
                    if target_tcp.get("mssql1433") is True:
                        add_sccm_attack_edge(
                            source_node, database_node, "CoerceAndRelayToMSSQL",
                            requirements + ["For the MSSQL route, TCP/1433 must be reachable on the separate database server."],
                            evidence + ["TCP/1433 is reachable on the target."])

        provider_nodes: dict[str, dict[str, Any]] = {}
        for provider in sccm_report.get("smsProviders", []):
            hostname = scalar(provider.get("hostname")).strip().rstrip(".")
            if not hostname:
                continue
            target_item = report_computer(hostname)
            target_computer = graph_computer(hostname)
            for site in sites_for(target_item or {}):
                site_code = scalar(site.get("siteCode")).strip()
                key = f"{site_code.casefold()}::{hostname.casefold()}"
                provider_node = provider_nodes.get(key)
                if provider_node is None:
                    provider_node = {
                        "id": f"sccm-provider::{domain.casefold()}::{key}",
                        "name": f"SMS Provider · {hostname}", "type": "sccm_provider", "domain": domain,
                        "sccm": {"role": "SMS Provider", "siteCode": site_code,
                                 "hostname": hostname, "endpoint": provider.get("endpoint", ""),
                                 "statusCode": provider.get("statusCode"),
                                 "authSchemes": provider.get("authSchemes", []),
                                 "ntlmSupported": provider.get("ntlmSupported") is True,
                                 "ntlmAdvertised": provider.get("ntlmAdvertised") is True},
                    }
                    nodes.append(provider_node)
                    provider_nodes[key] = provider_node
                    target_site = sites_by_code.get(site_code.casefold())
                    if target_site:
                        target_site["sccm"].setdefault("smsProviders", []).append(hostname)
                    if target_computer:
                        add_sccm_host_edge(provider_node, target_computer, "SMS Provider AdminService")
                if provider.get("ntlmSupported") is not True:
                    continue
                for source_item, source_node in active_site_servers(site):
                    if source_node["id"] == (target_computer or {}).get("id"):
                        continue
                    add_sccm_attack_edge(
                        source_node, provider_node, "CoerceAndRelayToSMSProvider",
                        ["The AdminService HTTP API must be reachable on the SMS Provider server.",
                         "The AdminService API must accept NTLM authentication; Configuration Manager 2509 and later reject NTLM and break this relay path.",
                         "The Primary Site Server computer account must have SMS Admins permissions to add a site administrator through the SMS_Admin API/WMI class.",
                         "The site Management Point and SMS Provider server names or addresses must be known.",
                         "The primary site server must be coercible into authenticating to the relay."],
                        [f"AdminService endpoint on SMS Provider {hostname}: {provider.get('endpoint', 'unknown')}.",
                         f"HTTP status: {provider.get('statusCode', 'unknown')}; offered schemes: {', '.join(provider.get('authSchemes') or []) or 'not reported'}.",
                         ("NTLM was explicitly advertised by the endpoint."
                          if provider.get("ntlmAdvertised") else
                          "Negotiate was advertised; AdminService can negotiate NTLM before Configuration Manager 2509."),
                         "Relay target resource: /AdminService/wmi/SMS_Admin.",
                         *(f"Site Management Point: {scalar(point.get('hostname'))}."
                           for point in sccm_report.get("managementPoints", [])
                           if normalize_host(point.get("siteCode")) == normalize_host(site.get("siteCode"))
                           and scalar(point.get("hostname")).strip())])

        passive_servers = []
        for item in report_computers:
            smb = item.get("smb") or {}
            state = normalize_host(item.get("siteServerConfiguration") or smb.get("siteServerConfiguration"))
            if state == "passive":
                node = graph_computer(scalar(item.get("hostname")))
                if node and smb.get("status") in {"authenticated", "authentication-failed"}:
                    passive_servers.append((item, node))
        for site in sccm_report.get("sites", []):
            for passive_item, passive_node in passive_servers:
                passive_codes = item_site_codes(passive_item)
                site_code = normalize_host(site.get("siteCode"))
                if passive_codes and site_code and site_code not in passive_codes:
                    continue
                for _, active_node in active_site_servers(site):
                    active_item = report_computer(scalar(active_node.get("dNSHostName") or active_node.get("name"))) or {}
                    active_smb = active_item.get("smb") or {}
                    if passive_node["id"] == active_node["id"]:
                        continue
                    signing_required = active_smb.get("signingRequired")
                    signing_status = ("conditional" if signing_required is False else
                                      "blocked" if signing_required is True else "unknown")
                    passive_detection = scalar(passive_item.get("siteServerDetection"))
                    evidence = [f"Passive site server: {scalar(passive_item.get('hostname'))}.",
                                f"Active site server: {scalar(active_item.get('hostname') or active_node.get('dNSHostName') or active_node.get('name'))}.",
                                f"Both servers are associated with site {scalar(site.get('siteCode')) or 'unknown'}.",
                                (f"Passive-server evidence: {passive_detection}." if passive_detection else
                                 "Passive site-server status was collected from SMB shares or System Management rights."),
                                ("SMB signing is not required on the active site server."
                                 if signing_required is False else
                                 "SMB signing is currently required on the active site server; this blocks the relay prerequisite."
                                 if signing_required is True else
                                 "SMB signing requirement on the active site server could not be determined.")]
                    add_sccm_attack_edge(
                        passive_node, active_node, "CoerceAndRelayPassiveToActiveServer",
                        ["A passive site server must be present and reachable.",
                         "The NetBIOS name, FQDN, or IP address of both the passive and active site servers must be known.",
                         "SMB signing must not be required on the active site server.",
                         "The passive server must be coercible into authenticating to the relay."],
                        evidence, status=signing_status, traversable=signing_required is not True)
    machine_account_quota = next((scalar(attr(entry, "ms-DS-MachineAccountQuota"))
                                  for entry in entries
                                  if classify(entry) == "domain"
                                  and attr(entry, "ms-DS-MachineAccountQuota") is not None), None)
    if sccm_report is not None:
        # These standard publication ACLs are useful in object details but
        # redundant as attack-path edges from the SCCM site servers themselves.
        site_server_accounts = set()
        for item in sccm_report.get("computers", []):
            smb = item.get("smb") or {}
            state = scalar(item.get("siteServerConfiguration")).strip().casefold()
            roles = {scalar(role).strip().casefold().replace("_", "-")
                     for role in [*(item.get("ldapRoles") or []), *(smb.get("roles") or [])]}
            if state not in {"active", "passive"} and "site-server" not in roles:
                continue
            hostname = scalar(item.get("hostname")).strip().rstrip(".").casefold()
            if hostname:
                short_name = hostname.split(".", 1)[0]
                site_server_accounts.update({short_name, f"{short_name}$", hostname})
        node_by_id = {node["id"]: node for node in nodes}
        for edge in edges:
            if edge.get("kind") != "dacl":
                continue
            target = node_by_id.get(edge.get("target"), {})
            target_dn = re.sub(r"\s+", "", scalar(target.get("dn"))).casefold()
            if target.get("type") != "container" or not target_dn.startswith("cn=systemmanagement,cn=system,"):
                continue
            rights = {part.strip().upper() for part in re.split(r"[|,;]", scalar(edge.get("right")))
                      if part.strip()}
            if "GENERIC_ALL" not in rights:
                continue
            trustee = scalar(edge.get("sourceName")).strip().rsplit("\\", 1)[-1].casefold()
            if trustee in site_server_accounts:
                edge["sccmPublishingAcl"] = True
    dataset = {"schema": "daclgraph/v1", "domain": domain,
            "collectedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "filters": {"types": sorted(selected)}, "nodes": nodes, "edges": edges,
            "adcsAssessment": adcs_report,
            "stats": {"objects": len([n for n in nodes if n["type"] not in {"trustee", "adcs_finding"}]),
                      "machineAccountQuota": machine_account_quota,
                      "trustees": len([n for n in nodes if n["type"] == "trustee"]),
            "aces": len({(e["target"], e.get("descriptorAttribute", "nTSecurityDescriptor"), e["aceIndex"])
                         for e in edges if e.get("kind") == "dacl" or "aceIndex" in e}),
                      "adcsFindings": len({(e.get("esc", "ESC13" if e.get("adcsEsc13") else ""), e.get("templateDN", ""))
                                           for e in edges if e.get("kind") == "adcs_esc" or e.get("adcsEsc13")}),
                      "adcsCandidates": sum(item["status"] == "candidate" for item in adcs_report),
                      "adcsRemoteChecks": sum(item["status"] == "requires_remote_check" for item in adcs_report)}}
    if sccm_report is not None:
        dataset["sccm"] = sccm_report
    return dataset
