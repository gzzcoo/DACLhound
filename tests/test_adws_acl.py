import base64
import contextlib
import io
import struct
import unittest
import uuid
from xml.etree import ElementTree as ET

from daclhound.adws._protocol import ADWSConnect, NTLMAuth
from daclhound.adws.acl import _mask_rights
from daclhound.adws.collector import ADWSCollector, _entry
from daclhound.analysis import _analysis_edge_label
from daclhound.collector import build_dataset
from daclhound.common import trustee_display_name


def sid(subauthorities):
    return (bytes((1, len(subauthorities))) + bytes.fromhex("000000000005") +
            b"".join(struct.pack("<I", value) for value in subauthorities))


def property_write_descriptor(guid, trustee):
    owner = sid([21, 1, 2, 3, 500])
    body = struct.pack("<II", 0x20, 1) + guid.bytes_le + trustee
    ace = struct.pack("<BBH", 0x05, 0, len(body) + 4) + body
    dacl = struct.pack("<BBHHH", 2, 0, len(ace) + 8, 1, 0) + ace
    dacl_offset = 20 + len(owner)
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 20, 0, 0, dacl_offset)
    return header + owner + dacl


class ADWSACLTests(unittest.TestCase):
    def test_expanded_directory_access_masks_match_generic_rights(self):
        self.assertEqual(_mask_rights(0x000F01FF), "GENERIC_ALL")
        self.assertEqual(_mask_rights(0x00020028), "GENERIC_WRITE")
        self.assertEqual(_mask_rights(0x00020094), "GENERIC_READ")
        self.assertEqual(_mask_rights(0x00020004), "GENERIC_EXECUTE")
        self.assertEqual(_mask_rights(0x000200BC), "GENERIC_WRITE|GENERIC_READ")
        self.assertEqual(_mask_rights(0x0002003C),
                         "GENERIC_WRITE|READ_PROP|LIST_CHILD")
        self.assertEqual(_mask_rights(0x00000030, object_scoped=True), "WRITE_PROP|READ_PROP")
        self.assertEqual(_mask_rights(0x000F01FF, object_scoped=True), "GENERIC_ALL")

    def test_generic_high_bits_and_mixed_directory_masks(self):
        self.assertEqual(_mask_rights(0x10000000), "GENERIC_ALL")
        self.assertEqual(_mask_rights(0x40000000), "GENERIC_WRITE")
        self.assertEqual(_mask_rights(0x80000000), "GENERIC_READ")
        self.assertEqual(_mask_rights(0x20000000), "GENERIC_EXECUTE")
        self.assertIn("GENERIC_WRITE", _mask_rights(0x000F01BD))
        self.assertIn("GENERIC_READ", _mask_rights(0x000F01BD))
        self.assertEqual(_mask_rights(0), "NO_ACCESS")

    def test_remaining_standard_and_unknown_access_mask_bits_are_preserved(self):
        self.assertEqual(_mask_rights(0x00100000), "SYNCHRONIZE")
        self.assertEqual(_mask_rights(0x01000000), "ACCESS_SYSTEM_SECURITY")
        self.assertEqual(_mask_rights(0x02000000), "MAXIMUM_ALLOWED")
        self.assertEqual(_mask_rights(0x00000800), "UNKNOWN_0x00000800")
        self.assertEqual(_mask_rights(0x00020028, object_scoped=True),
                         "READ_CONTROL|WRITE_PROP|WRITE_VALIDATED")

    def test_special_sid_placeholders_have_readable_names(self):
        self.assertEqual(trustee_display_name("S-1-5-10"), "Principal Self")
        self.assertEqual(trustee_display_name("S-1-3-0"), "Creator Owner")
        self.assertEqual(trustee_display_name("S-1-5-32-517"), "S-1-5-32-517")

    def test_rootdse_context_parser_accepts_namespace_and_case_variations(self):
        response = b"""<s:Envelope xmlns:s="urn:soap" xmlns:x="urn:ad-data" xmlns:y="urn:ad-value">
          <x:DefaultNamingContext><y:Value>DC=example,DC=test</y:Value></x:DefaultNamingContext>
          <x:configurationNamingContext><y:value>CN=Configuration,DC=example,DC=test</y:value></x:configurationNamingContext>
        </s:Envelope>"""

        class FakeNMF:
            def send(self, _data):
                pass

            def recv(self):
                return response

        client = object.__new__(ADWSConnect)
        contexts = client.get_rootdse_contexts("dc.example.test", FakeNMF())
        self.assertEqual(contexts["defaultNamingContext"], "DC=example,DC=test")
        self.assertEqual(contexts["configurationNamingContext"], "CN=Configuration,DC=example,DC=test")

    def test_collection_derives_default_naming_context_from_domain(self):
        class FakeSocket:
            def close(self):
                pass

        class FakeClient:
            _nmf = type("NMF", (), {"_sock": FakeSocket()})()

            def get_rootdse_contexts(self, *_args):
                return {}

        collector = ADWSCollector("dc.example.test", "example.test", "user", "password")
        collector._client = lambda: FakeClient()
        collector._resolve_schema_guids = lambda: None
        searched_bases = []

        def fake_search(_client, base, _filter, _attrs):
            searched_bases.append(base)
            return []

        collector._search = fake_search
        with contextlib.redirect_stderr(io.StringIO()):
            entries = collector.collect({"users"}, {"users": ("user", "(objectClass=user)")},
                                        "distinguishedName", include_adcs=False)
        self.assertEqual(entries, [])
        self.assertEqual(searched_bases, ["DC=example,DC=test"])

    def test_nt_hash_formats_accept_bare_nt_hash_and_lm_nt_pair(self):
        nt_hash = "a" * 32
        lm_hash = "b" * 32
        self.assertEqual(NTLMAuth(hashes=f":{nt_hash}").nt, nt_hash)
        parsed = NTLMAuth(hashes=f"{lm_hash}:{nt_hash}")
        self.assertEqual(parsed.lm, lm_hash)
        self.assertEqual(parsed.nt, nt_hash)

    def test_missing_enumeration_context_is_reported_as_error(self):
        class FailedClient:
            def pull(self, **_kwargs):
                return None

        collector = ADWSCollector("dc.example.test", "example.test", "user", "password")
        with self.assertRaisesRegex(RuntimeError, "no enumeration result"):
            collector._search(FailedClient(), "DC=example,DC=test", "(objectClass=user)", ["name"])

    def test_attribute_write_ace_keeps_property_scope_in_graph(self):
        namespaces = {
            "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "xsi": "http://www.w3.org/2001/XMLSchema-instance",
        }
        item = ET.Element("{urn:daclhound:test}entry")

        def add(name, value, binary=False):
            attr = ET.SubElement(item, f"{{{namespaces['addata']}}}{name}")
            node = ET.SubElement(attr, f"{{{namespaces['ad']}}}value")
            if binary:
                node.set(f"{{{namespaces['xsi']}}}type", "ad:base64Binary")
                value = base64.b64encode(value).decode("ascii")
            node.text = value

        add("distinguishedName", "CN=Target,DC=example,DC=test")
        add("sAMAccountName", "Target")
        add("userAccountControl", "4194304")
        for object_class in ("top", "person", "user"):
            add("objectClass", object_class)
        target_sid = sid([21, 1, 2, 3, 1200])
        trustee_sid = sid([21, 1, 2, 3, 1104])
        attribute_guid = uuid.UUID("bf967a68-0de6-11d0-a285-00aa003049e2")
        add("objectSid", target_sid, binary=True)
        add("nTSecurityDescriptor", property_write_descriptor(attribute_guid, trustee_sid), binary=True)

        entry = _entry(item, ["distinguishedName", "sAMAccountName", "userAccountControl", "objectClass",
                              "objectSid", "nTSecurityDescriptor"],
                       {str(attribute_guid).upper(): "userAccountControl"})
        entry["nTSecurityDescriptor"]["ACL"].append({
            "Trustee": "S-1-5-10", "Type": "ACCESS_ALLOWED", "Right": "CONTROL_ACCESS",
            "ObjectType": "Change Password", "Flags": "",
        })
        dataset = build_dataset([entry], "example.test", {"user"})
        edge = next(edge for edge in dataset["edges"] if edge["kind"] == "dacl")

        self.assertEqual(edge["sourceName"], "S-1-5-21-1-2-3-1104")
        self.assertEqual(edge["right"], "WRITE_PROP")
        self.assertEqual(edge["objectType"], "userAccountControl")
        self.assertEqual(_analysis_edge_label(edge), "WriteUserAccountControl")
        user = next(node for node in dataset["nodes"] if node["type"] == "user")
        self.assertTrue(user["asrepRoastable"])
        self_node = next(node for node in dataset["nodes"] if node.get("sid") == "S-1-5-10")
        self.assertEqual(self_node["name"], "Principal Self")


if __name__ == "__main__":
    unittest.main()
