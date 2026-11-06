import socket
from enum import IntEnum
from typing import Type

import impacket.structure

from .encoder import Encoder
from .ms_nns import NNS

"""
[MC-NMF]: .NET Message Framing Protocol.  This is the initiator (client) implementation.
Only Duplex mode is implmented.

"""


class RecordType(IntEnum):
    """
    Protocol for record exchange

    [MC-NMF]: 2.2.1
    """

    VERSION = 0x0
    MODE = 0x1
    VIA = 0x2
    KNOWN_ENCODING = 0x3
    EXTENSIBLE_ENCODING = 0x4
    UNSIZED_ENVELOPE = 0x5
    SIZED_ENVELOPE = 0x6
    END = 0x7
    FAULT = 0x8
    UPGRADE_REQUEST = 0x9
    UPGRADE_RESPONSE = 0xA
    PREAMBLE_ACK = 0xB
    PREAMBLE_END = 0xC


class Mode(IntEnum):
    """Communication mode

    [MC-NMF]: 2.2.3.2
    """

    SINGELTON_UNSIZED = 0x1
    DUPLEX = 0x2
    SIMPLEX = 0x3
    SINGLETON_SIZED = 0x4


class KnownEncoding(IntEnum):
    """Encoding Envelope Records

    [MC-NMF]: 2.2.3.4.1
    """

    # soap 1.1
    SOAP1_1_UTF8 = 0x0  # [RFC2279]
    SOAP1_1_UTF16 = 0x1  # [RFC2781]
    SOAP1_1_UNICODE_LE = 0x2

    # soap 1.2
    SOAP1_2_UTF8 = 0x3
    SOAP1_2_UTF16 = 0x4
    SOAP1_2_UNICODE = 0x5
    SOAP1_2_MTOM = 0x6  # [SOAP-MTOM]
    SOAP1_2_BINARY = 0x7  # [MC-NBFS]
    SOAP1_2_BINARY_INBAND_DICT = 0x8  # [MC-NBFSE]


class NMFServerFault(Exception): ...


class NMFUnknownRecord:
    def __init__(self, data=""):
        raise NMFServerFault(f"NMFUnknownRecord type {data}")


class NMFRecord(impacket.structure.Structure):
    structure: tuple[tuple[str, str] | tuple[str, str, object], ...]

    def send(self, sock: socket.socket | NNS):
        sock.sendall(self.getData())

    @staticmethod
    def encode_size(size: int) -> bytes:
        """NMF variable size encoding for records.

        [MC-NMF]: 2.2.2

        Args:
            size (int): size of the record payload

        Returns:
            bytes: packed and encoded size as bytes
        """
        MAXMBI = 0x7F
        if size < 0:
            raise ValueError("Signed numbers are not supported")

        if size <= MAXMBI:
            return bytes([size])

        result = []
        for _ in range(5):
            byte = size & MAXMBI
            size >>= 7
            if size != 0:
                byte |= MAXMBI + 1
            result.append(byte)

            if size == 0:
                break

        return bytes(result)

    @staticmethod
    def decode_size(encoded_data: bytes) -> tuple[int, int, bytes]:
        """NMF decode size of record payload.

        Returns the size of the payload, and also the number of bytes the size
        value takes.  The size field is variable length.

        To use this method, first slice off the record type so that the first
        field in the encoded_data is the size feild

        The size feild can be max 5 bytes long.

        [MC-NMF]: 2.2.2

        Args:
            encoded_data (bytes): payload with size included

        Returns:
            tuple[int, int, bytes]: size of the payload, the number of bytes in the size field, the payload
        """

        size = 0
        shift = 0
        len_length = 0

        max_len = min(len(encoded_data), 5)

        for i in range(max_len):
            byte = encoded_data[i]

            len_length += 1
            size |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return size, len_length, encoded_data[len_length:]
            shift += 7

            if size > 0xFFFFFFFF:
                raise ValueError("Size too big")

        return size, 1, encoded_data[1:]


class NMFVersion(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
    )

    def __init__(
        self, major_version: int = 0, minor_version: int = 0, data: None | bytes = None
    ):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.VERSION
            self["major_version"] = major_version
            self["minor_version"] = minor_version


class NMFMode(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("mode", ">B"),
    )

    def __init__(self, mode: int = 0, data: None | bytes = None):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.MODE
            self["mode"] = mode


class NMFVia(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("via_len", ":"),  # warning, this is variable length field
        ("via", ":"),
    )

    def __init__(self, via: str = "", data: None | bytes = None):
        """This record has variable length field encoding on the
        via_len field.  Reading 'via_len' will not return a correct
        value.

        Args:
            via (str): via to send
            data (bytes): a packed full length record
        """
        impacket.structure.Structure.__init__(self)
        if data:
            self["record_type"] = data[0]
            _, _, payload = self.decode_size(data[1:])
            self["via"] = payload.decode("utf-8")
        else:
            self["record_type"] = RecordType.VIA
            self["via_len"] = self.encode_size(len(via.encode("utf-8")))
            self["via"] = via.encode("utf-8")


class NMFKnownEncoding(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("encoding", ">B"),
    )

    def __init__(self, encoding: int = 0, data: None | bytes = None):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.KNOWN_ENCODING
            self["encoding"] = encoding


class NMFExtensibleEncoding(NMFRecord): ...


class NMFSizedEnvelope(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("size", ":"),
        ("payload", ":"),
    )

    def __init__(self, payload: bytes = bytes(), data: None | bytes = None):
        """This record has variable length field encoding on the
        'size' field.  Reading 'size' will not return a correct
        value.

        Args:
            payload (bytes): payload to send
            data (bytes): a packed sized envelope record
        """
        impacket.structure.Structure.__init__(self, data=data)
        if data:
            self["record_type"] = data[0]
            _, _, env_payload = self.decode_size(data[1:])
            self["payload"] = env_payload
        else:
            self["record_type"] = RecordType.SIZED_ENVELOPE
            self["size"] = self.encode_size(len(payload))
            self["payload"] = payload


class NMFEnd(NMFRecord):
    structure = (("record_type", ">B"),)

    def __init__(self, data: None | bytes = None):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.END


class NMFUnsizedEnvelope(NMFRecord): ...


class NMFFault(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("size", ":"),
        ("fault", ":"),
    )

    def __init__(self, fault: str = "", data: None | bytes = None):
        """This record has variable length field encoding on the
        'size' field.  Reading 'size' will not return a correct
        value.

        Args:
            fault (str): fault msg to send
            data (bytes): a packed full length record
        """
        impacket.structure.Structure.__init__(self, data=data)
        if data:
            self["record_type"] = data[0]
            _, _, payload = self.decode_size(data[1:])
            self["fault"] = payload.decode("utf-8")

        else:
            self["record_type"] = RecordType.FAULT
            self["size"] = self.encode_size(len(fault.encode("utf-8")))
            self["fault"] = fault.encode("utf-8")


class NMFUpgradeRequest(NMFRecord):
    structure = (
        ("record_type", ">B"),
        ("proto_len", ":"),
        ("proto", ":"),
    )

    def __init__(self, proto: str = "application/negotiate", data: None | bytes = None):
        """This record has variable length field encoding on the
        'proto_len' field.  Reading 'proto_len' will not return a correct
        value.

        Args:
            proto (str): proto to send
            data (bytes): a packed full length record
        """

        impacket.structure.Structure.__init__(self, data=data)

        if data:
            self["record_type"] = data[0]
            _, _, payload = self.decode_size(data[1:])
            self["proto"] = payload.decode("utf-8")
        else:
            self["record_type"] = RecordType.UPGRADE_REQUEST
            self["proto_len"] = self.encode_size(len(proto.encode("utf-8")))
            self["proto"] = proto.encode("utf-8")


class NMFUpgradeResponse(NMFRecord):
    structure = (("record_type", ">B"),)

    def __init__(self, data: None | bytes = None):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.UPGRADE_RESPONSE


class NMFPreambleEnd(NMFRecord):
    structure = (("record_type", ">B"),)

    def __init__(self, data: None | bytes = None):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.PREAMBLE_END


class NMFPreambleAck(NMFRecord):
    structure = (("record_type", ">B"),)

    def __init__(self, data: None | bytes = None):
        impacket.structure.Structure.__init__(self, data=data)
        if not data:
            self["record_type"] = RecordType.PREAMBLE_ACK


class NMFPreamble(NMFRecord):
    structure = (
        ("version", ":"),
        ("mode", ":"),
        ("via", ":"),
        ("encoding", ":"),
    )

    def __init__(
        self,
        version: tuple[int, int] = (1, 1),
        mode: int = 0,
        via: str = "",
        encoding: int = 0,
    ):
        impacket.structure.Structure.__init__(self)
        self["version"] = NMFVersion(*version).getData()
        self["mode"] = NMFMode(mode).getData()
        self["via"] = NMFVia(via).getData()
        self["encoding"] = NMFKnownEncoding(encoding).getData()


class NMFConnection:
    def __init__(
        self,
        nns: NNS,
        fqdn: str,
        mode: int = Mode.DUPLEX,
        encoding: int = KnownEncoding.SOAP1_2_BINARY_INBAND_DICT,
    ):
        """
        Args:
            nns (NNS): NNS Connection object
            fqdn (str): FQDN of endpoint we wish to talk to
        """

        self._nns: NNS = nns
        self._sock: socket.socket = nns._sock

        # before being upgraded, the transport is raw socket
        self._transport: NNS | socket.socket = self._sock

        self._mode = mode
        self._encoding = encoding
        self._fqdn = fqdn
        self._recv_buffer = b""

        self._encoder = Encoder(self._encoding)

    @staticmethod
    def _decode_size_from_buffer(data: bytes) -> tuple[int, int] | None:
        """Decode an NMF variable-length size when enough bytes are buffered."""
        size = 0
        shift = 0
        for index, byte in enumerate(data[:5], start=1):
            size |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return size, index
            shift += 7
        if len(data) < 5:
            return None
        raise ValueError("NMF record size exceeds the five-byte limit")

    def _recv_more(self) -> None:
        data = self._transport.recv(4096)
        if not data:
            raise ConnectionError("Connection closed while reading NMF record")
        self._recv_buffer += data

    def _recv_record_bytes(self) -> bytes:
        """Read exactly one NMF record and retain any following records."""
        fixed_record_sizes = {
            RecordType.VERSION: 3,
            RecordType.MODE: 2,
            RecordType.KNOWN_ENCODING: 2,
            RecordType.END: 1,
            RecordType.UPGRADE_RESPONSE: 1,
            RecordType.PREAMBLE_ACK: 1,
            RecordType.PREAMBLE_END: 1,
        }
        variable_record_types = {
            RecordType.VIA,
            RecordType.SIZED_ENVELOPE,
            RecordType.FAULT,
            RecordType.UPGRADE_REQUEST,
        }

        while not self._recv_buffer:
            self._recv_more()

        record_type = self._recv_buffer[0]
        if record_type in fixed_record_sizes:
            total_size = fixed_record_sizes[record_type]
            while len(self._recv_buffer) < total_size:
                self._recv_more()
        elif record_type in variable_record_types:
            size_info = None
            while size_info is None:
                size_info = self._decode_size_from_buffer(self._recv_buffer[1:])
                if size_info is None:
                    self._recv_more()
            payload_size, size_length = size_info
            total_size = 1 + size_length + payload_size
            while len(self._recv_buffer) < total_size:
                self._recv_more()
        else:
            total_size = 1

        record = self._recv_buffer[:total_size]
        self._recv_buffer = self._recv_buffer[total_size:]
        return record

    def _throw_if_not(self, expected: Type[NMFRecord], got: NMFRecord):
        """Allows for quick validation of expected responses.  If not expected
        checks for fault, and throws

        Args:
            expected (NMFRecord): the type you expected
            got (NMFRecord): what you have
        """

        if not isinstance(got, expected):
            if isinstance(got, NMFFault):
                raise ConnectionError(got["fault"])
            raise ConnectionError(
                f"Unexpected server response.  Expected  {expected['record_type']}, got {got['record_type']}"
            )

    def _upgrade(self):
        """Upgrade if using NNS for transport,
        otherwise do nothing.  This allows for support
        of unauthenticated transport for things like MEX
        """

        if not isinstance(self._nns, NNS):
            return

        NMFUpgradeRequest().send(self._transport)

        # wait for ack
        try:
            self._throw_if_not(NMFUpgradeResponse, self._recv())
        except Exception as exc:
            raise ConnectionError(f"ADWS NMF upgrade acknowledgement failed: {exc}") from exc

        # nns auth
        try:
            self._nns.authenticate()
        except Exception as exc:
            raise ConnectionError(f"ADWS NNS authentication handshake failed: {exc}") from exc

        # NNS authentication has its own framing. Do not carry buffered cleartext
        # NMF bytes across the transport upgrade.
        self._recv_buffer = b""

        # switch to upgraded transport now
        self._transport = self._nns

    def connect(self, resource: str):
        """Establish connection to server. Set up all the communication
        channels that are nessisary to begin data exchanges.

        Send NMF preamble
        Upgrade to NNS
        NNS Auth
        End NMF preamble

        Args:
            resource (str): Resource to request in the via

        Raises:
            NMFServerFault: Raises when the server ack upgrade request
            or the preamble end, indicating connection falure.
        """

        # send the preamble
        NMFPreamble(
            version=(1, 0),
            mode=self._mode,
            via=f"net.tcp://{self._fqdn}:9389/ActiveDirectoryWebServices/{resource}",
            encoding=self._encoding,
        ).send(self._transport)

        self._upgrade()

        # preamble end
        try:
            NMFPreambleEnd().send(self._transport)

            # wait for ack
            self._throw_if_not(NMFPreambleAck, self._recv())
        except Exception as exc:
            raise ConnectionError(f"ADWS protected NMF preamble acknowledgement failed: {exc}") from exc

    def _end_record(self) -> None:
        """Send an end record"""
        NMFEnd().send(self._transport)

    def send(self, data: str):
        """Send data to server in an envelope msg.  This assumes that
        the current mode is duplex or simplex.

        Args:
            data (str): data to send
        """
        encoding_data: bytes = self._encoder.encode(data)
        NMFSizedEnvelope(payload=encoding_data).send(self._transport)

    def recv(self) -> str:
        """Receive data from the transport mechanism.  Automatically
        decodes the data based on selected transport encoding
        type.

        Returns:
            (str): received and decoded data
        Raises:
            NMFServerFault: Raises if not data transport msg
        """
        pkt = self._recv()

        self._throw_if_not(NMFSizedEnvelope, pkt)

        return self._encoder.decode(pkt["payload"])

    def _recv(self) -> NMFRecord:
        """Read a packet from the network transport layer and
        return the object version of the packet

        Returns:
            NMFRecord: Correct NMF object
        """

        jump_table = {
            0x0: NMFVersion,
            0x1: NMFMode,
            0x2: NMFVia,
            0x3: NMFKnownEncoding,
            0x4: NMFExtensibleEncoding,
            0x5: NMFUnsizedEnvelope,
            0x6: NMFSizedEnvelope,
            0x7: NMFEnd,
            0x8: NMFFault,
            0x9: NMFUpgradeRequest,
            0xA: NMFUpgradeResponse,
            0xB: NMFPreambleAck,
            0xC: NMFPreambleEnd,
        }

        data = self._recv_record_bytes()

        record_type: int = data[0]

        # simplifed object factory, takes type and returns NMFRecords
        return jump_table.get(record_type, NMFUnknownRecord)(data=data)
