# tests/test_geosite_importer.py
import unittest
import tempfile
import os
import struct

from core import geosite_importer

def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value > 0:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def _encode_length_delimited(field_number: int, data: bytes) -> bytes:
    tag = (field_number << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data

def _encode_varint_field(field_number: int, value: int) -> bytes:
    tag = (field_number << 3) | 0
    return _encode_varint(tag) + _encode_varint(value)

class TestGeositeImporter(unittest.TestCase):

    def test_parse_protobuf_geosite(self):
        # Генерируем минимальный geosite.dat
        # DomainEntry: type=3 (domain), value="youtube.com"
        domain_entry = (
            _encode_varint_field(1, 3) +
            _encode_length_delimited(2, b"youtube.com")
        )
        
        # SiteGroup: tag="google", domain=[domain_entry]
        site_group = (
            _encode_length_delimited(1, b"google") +
            _encode_length_delimited(2, domain_entry)
        )
        
        # Upper level: fn=1 (site_group)
        geosite_data = _encode_length_delimited(1, site_group)

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(geosite_data)
            tmp_path = tf.name

        try:
            res = geosite_importer._parse_protobuf_geosite(tmp_path)
            self.assertIn("google", res)
            self.assertEqual(res["google"], ["youtube.com"])
        finally:
            os.remove(tmp_path)

    def test_parse_protobuf_geoip(self):
        # Генерируем минимальный geoip.dat
        # CidrEntry: ip=8.8.8.8 (4 bytes), prefix=32
        cidr_entry = (
            _encode_length_delimited(1, b"\x08\x08\x08\x08") +
            _encode_varint_field(2, 32)
        )
        
        # Country: tag="US", cidr=[cidr_entry]
        country = (
            _encode_length_delimited(1, b"US") +
            _encode_length_delimited(2, cidr_entry)
        )
        
        # Upper level: fn=1 (country)
        geoip_data = _encode_length_delimited(1, country)

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(geoip_data)
            tmp_path = tf.name

        try:
            res = geosite_importer._parse_protobuf_geoip(tmp_path)
            self.assertIn("US", res)
            self.assertEqual(res["US"], ["8.8.8.8/32"])
        finally:
            os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
