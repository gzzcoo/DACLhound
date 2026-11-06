import logging
import socket
import datetime
import struct

import impacket.examples.logger
import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from impacket.hresult_errors import ERROR_MESSAGES

from .encoder.records.utils import Net7BitInteger


def hexdump(data, length=16):
    def to_ascii(byte):
        if 32 <= byte <= 126:
            return chr(byte)
        else:
            return "."

    def format_line(offset, line_bytes):
        hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
        ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
        return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

    lines = []
    for i in range(0, len(data), length):
        line_bytes = data[i : i + length]
        lines.append(format_line(i, line_bytes))

    return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
    structure: tuple[tuple[str, str], ...]

    def send(self, sock: socket.socket):
        sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

    # During negotitiate, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ NTLMSSP

    # For Kerberos
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ krb5_blob
    #       |_ Kerberos ( AP REQ )

    ###

    # During challenge, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API, SPNEGO, no GSS-API headers )
    #     |_ NegTokenTarg ( NegTokenResp )
    #       |_ NTLMSSP

    def __init__(
        self, message_id: int, major_version: int, minor_version: int, payload: bytes
    ):
        impacket.structure.Structure.__init__(self)
        self["message_id"] = message_id
        self["major_version"] = major_version
        self["minor_version"] = minor_version
        self["payload"] = payload


class NNS_data(NNS_pkt):
    # NNS data message, used after auth is completed

    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )


class NNS_Signed_payload(impacket.structure.Structure):
    structure = (
        ("signature", ":"),
        ("cipherText", ":"),
    )


class MessageID:
    IN_PROGRESS: int = 0x16
    ERROR: int = 0x15
    DONE: int = 0x14


class NNS:
    """[MS-NNS]: .NET NegotiateStream Protocol

    The .NET NegotiateStream Protocol provides mutually authenticated
    and confidential communication over a TCP connection.

    It defines a framing mechanism used to transfer (GSS-API) security tokens
    between a client and server. It also defines a framing mechanism used
    to transfer signed and/or encrypted application data once the GSS-API
    security context initialization has completed.
    """

    def __init__(
        self,
        socket: socket.socket,
        fqdn: str,
        domain: str,
        username: str,
        password: str | None = None,
        nt: str = "",
        lm: str = "",
        kerberos: object | None = None,
    ):
        self._sock = socket

        self._nt = self._fix_hashes(nt)
        self._lm = self._fix_hashes(lm)

        self._username = username
        self._password = password

        self._domain = domain
        self._fqdn = fqdn
        self._kerberos = kerberos
        self._kerberos_key = None
        self._kerberos_gss = None
        self._recv_sequence = 0

        self._session_key: bytes = b""
        self._flags: int = -1
        self._sequence: int = 0

    def _fix_hashes(self, hash: str | bytes) -> bytes | str:
        """fixes up hash if present into bytes and
        ensures length is 32.

        If no hash is present, returns empty bytes

        Args:
            hash (str | bytes): nt or lm hash

        Returns:
            bytes: bytes version
        """

        if not hash:
            return ""

        if len(hash) % 2:
            hash = hash.zfill(32)

        return bytes.fromhex(hash) if isinstance(hash, str) else hash

    def seal(self, data: bytes) -> tuple[bytes, bytes]:
        """seals data with the current context

        Args:
            data (bytes): bytes to seal

        Returns:
            tuple[bytes, bytes]: output_data, signature
        """

        server = bool(
            self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        output, sig = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle,
        )

        return output, sig.getData()

    def recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.

        Args:
            _ (int, optional): For interoperability with socket.socket. Defaults to 0.

        Returns:
            bytes: unsealed nns message
        """
        first_pkt = self._recv()

        # if it isnt an envelope, throw it back
        if first_pkt[0] != 0x06:
            return first_pkt

        nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

        # its all just one packet
        if nmfsize < 0xFC30:
            return first_pkt

        # otherwise, we have a multi part message
        pkt = first_pkt
        nmfsize -= len(first_pkt[nmflenlen:])

        while nmfsize > 0:
            thisFragment = self._recv()

            pkt += thisFragment
            nmfsize -= len(thisFragment)

        return pkt

    def _recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.
        """
        nns_data = NNS_data()
        size = int.from_bytes(self._recv_exact(self._sock, 4), "little")
        payload = self._recv_exact(self._sock, size)
        nns_data["payload"] = payload

        if self._flags == -2:
            if self._kerberos_key.enctype == 23:
                return self._unwrap_kerberos_rc4(payload)
            clear, _ = self._kerberos_gss.GSS_Unwrap_LDAP(
                self._kerberos_key, payload, self._recv_sequence, direction="accept"
            )
            self._recv_sequence += 1
            return clear

        nns_signed_payload = NNS_Signed_payload()
        nns_signed_payload["signature"] = nns_data["payload"][0:16]
        nns_signed_payload["cipherText"] = nns_data["payload"][16:]

        clearText, sig = self.seal(nns_signed_payload["cipherText"])
        return clearText

    @staticmethod
    def _unwrap_gss_mech_token(data: bytes) -> bytes:
        """Remove a GSS APPLICATION 0 header and its mechanism OID."""
        if not data.startswith(b"\x60"):
            return data

        def read_length(value: bytes, offset: int) -> tuple[int, int]:
            first = value[offset]
            offset += 1
            if first < 0x80:
                return first, offset
            count = first & 0x7F
            return int.from_bytes(value[offset:offset + count], "big"), offset + count

        total, offset = read_length(data, 1)
        wrapped = data[offset:offset + total]
        if not wrapped.startswith(b"\x06"):
            raise ValueError("Kerberos GSS token omitted its mechanism OID")
        oid_size, offset = read_length(wrapped, 1)
        return wrapped[offset + oid_size:]

    def _unwrap_kerberos_rc4(self, payload: bytes) -> bytes:
        """Verify and decrypt an RFC 1964 Kerberos RC4 wrap token."""
        gss = self._kerberos_gss
        token_data = self._unwrap_gss_mech_token(payload)
        token_size = len(gss.WRAP().getData())
        if len(token_data) < token_size:
            raise ConnectionError("ADWS returned a truncated Kerberos RC4 wrap token")
        token = gss.WRAP(token_data[:token_size])
        key = self._kerberos_key.contents
        kseq = HMAC.new(key, struct.pack("<L", 0), MD5).digest()
        kseq = HMAC.new(kseq, token["SGN_CKSUM"], MD5).digest()
        seq_raw = ARC4.new(kseq).decrypt(token["SND_SEQ"])
        sequence = int.from_bytes(seq_raw[:4], "big")
        if seq_raw[4:] != b"\xff" * 4 or sequence != self._recv_sequence:
            raise ConnectionError("ADWS Kerberos RC4 wrap token has an invalid direction or sequence")
        local_key = bytes(value ^ 0xF0 for value in key)
        kcrypt = HMAC.new(local_key, struct.pack("<L", 0), MD5).digest()
        kcrypt = HMAC.new(kcrypt, seq_raw[:4], MD5).digest()
        clear = ARC4.new(kcrypt).decrypt(token["Confounder"] + token_data[token_size:])
        if len(clear) < 9:
            raise ConnectionError("ADWS returned invalid Kerberos RC4 protected data")
        confounder, padded = clear[:8], clear[8:]
        pad_length = padded[-1]
        if pad_length > 8 or (pad_length and padded[-pad_length:] != bytes((pad_length,)) * pad_length):
            raise ConnectionError("ADWS Kerberos RC4 wrap token has invalid padding")
        data = padded[:-pad_length] if pad_length else padded
        signed = MD5.new(struct.pack("<L", 13) + token.getData()[:8] + confounder + padded).digest()
        expected = HMAC.new(HMAC.new(key, b"signaturekey\0", MD5).digest(), signed, MD5).digest()[:8]
        if expected != token["SGN_CKSUM"]:
            raise ConnectionError("ADWS Kerberos RC4 wrap token signature validation failed")
        self._recv_sequence += 1
        return data

    def sendall(self, data: bytes):
        """send to server in NTLM sealed NNS data packet via tcp socket.

        Args:
            data (bytes): utf-16le encoded payload data
        """

        if self._kerberos_key is not None:
            # ADWS uses the LDAP GSS wrap profile for both AES and RC4. The
            # generic RC4 GSS_Wrap omits the LDAP terminator/mech token format.
            cipher_text, token = self._kerberos_gss.GSS_Wrap_LDAP(
                self._kerberos_key, data, self._sequence, direction="init", encrypt=True
            )
            pkt = NNS_data()
            pkt["payload"] = token + cipher_text
            logging.debug(
                "Kerberos NNS send: enctype=%d sequence=%d clear_len=%d wrapped_len=%d",
                self._kerberos_key.enctype,
                self._sequence,
                len(data),
                len(pkt["payload"]),
            )
            self._sock.sendall(pkt.getData())
            self._sequence += 1
            return

        cipherText, sig = impacket.ntlm.SEAL(
            self._flags,
            self._client_signing_key,
            self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._client_sealing_handle,
        )

        # build the NNS data packet to use
        pkt = NNS_data()

        # then we build the payload, which is the signature prepended
        # on the actual ciphertext.  This goes in the payload of
        # the NNS data packet
        payload = NNS_Signed_payload()
        payload["signature"] = sig
        payload["cipherText"] = cipherText
        pkt["payload"] = payload.getData()

        self._sock.sendall(pkt.getData())

        # and we increment the sequence number after sending
        self._sequence += 1

    def auth_ntlm(self) -> None:
        """Authenticate to the dest with NTLMV2 authentication"""

        # Initial negotiation sent from client
        NegTokenInit: impacket.spnego.SPNEGO_NegTokenInit
        NtlmSSP_nego: impacket.ntlm.NTLMAuthNegotiate

        # Generate a NTLMSSP
        NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
            workstation="",  # These fields don't get populated for some reason
            domain="",  # These fields don't get populated for some reason
            signingRequired=True,  # TODO: Somehow determine this; can we send a Negotiate Protocol Request and derive this dynamically?
            use_ntlmv2=True,  # TODO: See above comment
        )

        # Generate the NegTokenInit
        # Impacket has this inherit from GSSAPI, so we will also have the OID and other headers :D
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
        ]
        NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

        # Fit it all into an NNS NTLMSSP_NEGOTIATE Message
        # Begin authentication ( NTLMSSP_NEGOTIATE )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)

        # Response with challenge from server
        NNS_msg_chall: NNS_handshake
        s_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall: impacket.ntlm.NTLMAuthChallenge

        # Receive the NNS NTLMSSP_Challenge
        NNS_msg_chall = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # Extract the NegTokenResp ( NegTokenTarg )
        # Note: Potentially consider SupportedMech from s_NegTokenTarg for determining stuff like signing?
        s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

        # Create an NtlmAuthChallenge from the NTLMSSP ( ResponseToken )
        NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

        # TODO: see if this is relevant https://github.com/fortra/impacket/blob/15eff8805116007cfb59332a64194a5b9c8bcf25/impacket/smb3.py#L1015
        # if NTLMSSP_chall[ 'TargetInfoFields_len' ] > 0:
        #     av_pairs   = impacket.ntlm.AV_PAIRS( NTLMSSP_chall[ 'TargetInfoFields' ][ :NTLMSSP_chall[ 'TargetInfoFields_len' ] ] )
        #     if av_pairs[ impacket.ntlm.NTLMSSP_AV_HOSTNAME ] is not None:
        #         print( "TODO AV PAIRS IDK IF ITS RELEVANT" )

        # Response with authentication from client
        c_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall_resp: impacket.ntlm.NTLMAuthChallengeResponse

        # Create the NTLMSSP challenge response
        # If password is used, then the lm and nt hashes must be pass
        # an empty str, NOT, empty byte str.......
        NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=NtlmSSP_nego,
            type2=NTLMSSP_chall.getData(),
            user=self._username,
            password=self._password,
            domain=self._domain,
            lmhash=self._lm,
            nthash=self._nt,
        )

        # set up info for crypto
        self._flags = NTLMSSP_chall_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            logging.debug("We are doing extended ntlm security")
            self._client_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key
            )
            self._server_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key, "Server"
            )
            self._client_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key
            )
            self._server_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key, "Server"
            )

            # prepare keys to handle states
            cipher1 = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher1.encrypt
            cipher2 = ARC4.new(self._server_sealing_key)
            self._server_sealing_handle = cipher2.encrypt

        else:
            logging.debug("We are doing basic ntlm auth")
            # same key for both ways
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt

        # Fit the challenge response into the ResponseToken of our NegTokenTarg
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

        # Fit our challenge response into an NNS message
        # Send the NTLMSSP_AUTH ( challenge response )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Response from server ending handshake
        NNS_msg_done: NNS_handshake

        # Check for success
        NNS_msg_done = NNS_handshake(
            message_id=int.from_bytes(self._sock.recv(1), "big"),
            major_version=int.from_bytes(self._sock.recv(1), "big"),
            minor_version=int.from_bytes(self._sock.recv(1), "big"),
            payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
        )

        # check for errors
        if NNS_msg_done["message_id"] == 0x15:
            err_type, err_msg = ERROR_MESSAGES[
                int.from_bytes(NNS_msg_done["payload"], "big")
            ]
            raise SystemExit(f"[-] NTLM Auth Failed with error {err_type} {err_msg}")

    def authenticate(self) -> None:
        """Run the selected NNS security mechanism."""
        if self._kerberos is None:
            self.auth_ntlm()
        else:
            self.auth_kerberos()

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("ADWS closed the connection during Kerberos negotiation")
            data.extend(chunk)
        return bytes(data)

    def auth_kerberos(self) -> None:
        """Authenticate NNS with a Kerberos ccache using Impacket in-process."""
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AP_REQ, Authenticator, AP_REP, EncAPRepPart, TGS_REP, seq_set
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import getKerberosTGS
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        from impacket.krb5.crypto import Key, _enctype_table
        from impacket.krb5.gssapi import GSSAPI
        from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech, ASN1_AID, ASN1_OID, asn1encode
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type.univ import noValue

        cache_path = getattr(self._kerberos, "ccache_path", None)
        realm = self._domain.rstrip(".").upper()
        cache_data = getattr(self._kerberos, "ccache_data", None)
        ccache = CCache(cache_data) if cache_data else CCache.loadFile(cache_path)
        if ccache is None or ccache.principal is None:
            raise RuntimeError("Kerberos ccache is empty or unreadable")
        principal_name = ccache.principal.prettyPrint().decode("utf-8", "replace")
        if "@" in principal_name:
            realm = principal_name.rsplit("@", 1)[1].upper()
        target_spn = f"LDAP/{self._fqdn.rstrip('.')}"
        tgs_cred = ccache.getCredential(f"{target_spn}@{realm}", anySPN=False)
        if tgs_cred is not None:
            tgs = tgs_cred.toTGS()
            encoded_tgs = tgs["KDC_REP"]
            cipher, session_key = tgs["cipher"], tgs["sessionKey"]
        else:
            tgt_cred = ccache.getCredential(f"krbtgt/{realm}@{realm}", anySPN=False)
            if tgt_cred is None:
                raise RuntimeError(f"No TGT or {target_spn} service ticket found in the Kerberos ccache")
            tgt = tgt_cred.toTGT()
            service = Principal(target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            encoded_tgs, cipher, _old_key, session_key = getKerberosTGS(
                service, realm, getattr(self._kerberos, "kdc_host", None),
                tgt["KDC_REP"], tgt["cipher"], tgt["sessionKey"]
            )

        decoded_tgs = decoder.decode(encoded_tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decoded_tgs["ticket"])
        client = ccache.principal.toPrincipal()
        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags([constants.APOptions.mutual_required.value])
        seq_set(ap_req, "ticket", ticket.to_asn1)
        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = realm
        seq_set(authenticator, "cname", client.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)
        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003
        from impacket.krb5.gssapi import CheckSumField
        checksum = CheckSumField()
        checksum["Lgth"] = 16
        checksum["Flags"] = 0x10 | 0x20 | 0x02 | 0x04 | 0x08
        authenticator["cksum"]["checksum"] = checksum.getData()
        authenticator["seq-number"] = 0
        encrypted = cipher.encrypt(session_key, 11, encoder.encode(authenticator), None)
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = encrypted

        # GSS initial-context token containing the Kerberos AP-REQ.
        from impacket.krb5.gssapi import KRB5_AP_REQ
        gss_token = (struct.pack("B", ASN1_AID) + asn1encode(
            struct.pack("B", ASN1_OID) + asn1encode(TypesMech["KRB5 - Kerberos 5"])
            + KRB5_AP_REQ + encoder.encode(ap_req)))
        negotiate = SPNEGO_NegTokenInit()
        negotiate["MechTypes"] = [
            TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            TypesMech["KRB5 - Kerberos 5"],
            TypesMech["NEGOEX - SPNEGO Extended Negotiation Security Mechanism"],
            TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"],
        ]
        negotiate["MechToken"] = gss_token
        NNS_handshake(MessageID.IN_PROGRESS, 1, 0, negotiate.getData()).send(self._sock)

        header = self._recv_exact(self._sock, 5)
        message_id, major, minor = header[0], header[1], header[2]
        payload_len = int.from_bytes(header[3:5], "big")
        response = self._recv_exact(self._sock, payload_len)
        if message_id == MessageID.ERROR:
            error_code = int.from_bytes(response, "big")
            error_name, error_text = ERROR_MESSAGES.get(
                error_code,
                ("ERROR_TRUST_FAILURE", "The network logon failed") if error_code == 0x6FE
                else (f"0x{error_code:08x}", "Unknown Windows error"),
            )
            raise RuntimeError(f"ADWS rejected Kerberos authentication ({error_name}: {error_text})")
        if message_id != MessageID.DONE:
            raise RuntimeError(f"Unexpected NNS Kerberos response message 0x{message_id:02x}")
        rep_part = None
        if response:
            token = SPNEGO_NegTokenResp(response)
            if "ResponseToken" in token.fields:
                response_token = self._unwrap_gss_mech_token(bytes(token["ResponseToken"]))
                KRB5_AP_REP = b"\x02\x00"
                if response_token.startswith(KRB5_AP_REP):
                    response_token = response_token[len(KRB5_AP_REP):]
                ap_rep = decoder.decode(response_token, asn1Spec=AP_REP())[0]
                if int(ap_rep["enc-part"]["etype"]) != cipher.enctype:
                    raise RuntimeError("ADWS AP-REP encryption type did not match the service ticket")
                clear = cipher.decrypt(session_key, 12, ap_rep["enc-part"]["cipher"].asOctets())
                rep_part = decoder.decode(clear, asn1Spec=EncAPRepPart())[0]
        if rep_part is not None and rep_part["subkey"].hasValue():
            key_type = int(rep_part["subkey"]["keytype"])
            self._kerberos_key = Key(key_type, rep_part["subkey"]["keyvalue"].asOctets())
        else:
            key_type = cipher.enctype
            self._kerberos_key = session_key
        self._kerberos_gss = GSSAPI(_enctype_table[key_type]())
        self._sequence = 0
        self._recv_sequence = (int(rep_part["seq-number"])
                               if rep_part is not None and rep_part["seq-number"].hasValue() else 0)

        logging.debug(
            "Kerberos NNS context established: enctype=%d ap_rep=%s subkey=%s server_sequence=%d",
            self._kerberos_key.enctype,
            rep_part is not None,
            bool(rep_part is not None and rep_part["subkey"].hasValue()),
            self._recv_sequence,
        )

        # Mark that subsequent receive packets use GSS wrap tokens.
        self._flags = -2
