import pathlib
import struct
from dataclasses import dataclass

import pefile
from Crypto.Cipher import AES
from Crypto.Util import Padding


# TODO: move these constants to a config file (or try to compute the offsets?)
KEY = bytes(16)
ENCRYPTED_SECTIONS_TABLE_OFFSET = 0x0


@dataclass
class EncryptedSection:
    rva: int
    encrypted_size: int
    decrypted_size: int
    encrypted_checksum: int
    decrypted_checksum: int
    padding: bytes


class EA_DRM:

    def __init__(self, pe_path: str):
        self._pe_path = pathlib.Path(pe_path)
        self._pe = pefile.PE(pe_path, fast_load=True)

    
    def decrypt_sections(self):
        count = self._read(ENCRYPTED_SECTIONS_TABLE_OFFSET, 'B')
        for i in range(count):
            offset = ENCRYPTED_SECTIONS_TABLE_OFFSET + 0x1 + i * 0x30
            encrypted_section = EncryptedSection(
                rva=self._read(offset + 0x0, '<L'),
                encrypted_size=self._read(offset + 0x4, '<L'),
                decrypted_size=self._read(offset + 0x8, '<L'),
                encrypted_checksum=self._read(offset + 0x10, '<Q'),
                decrypted_checksum=self._read(offset + 0x18, '<Q'),
                padding=self._read(offset + 0x20, '16B'),
            )
            self._decrypt_section(encrypted_section)


    def _decrypt_section(self, encrypted_section: EncryptedSection) -> None:
        encrypted_data = self._pe.get_data(encrypted_section.rva, encrypted_section.encrypted_size)
        assert len(encrypted_data) == encrypted_section.encrypted_size
        
        aes = AES.new(
            key=KEY,
            mode=AES.MODE_CBC,
            iv=bytes(16),
        )
        
        decrypted_data = Padding.unpad(aes.decrypt(encrypted_data), AES.block_size)
        assert len(decrypted_data) == encrypted_section.decrypted_size

        # TODO: compute and verify checksums

        self._pe.set_bytes_at_rva(encrypted_section.rva, decrypted_data)

    
    def _read(self, offset: int, format: str):
        rva = self._pe.get_rva_from_offset(offset)
        buffer = self._pe.get_data(rva, struct.calcsize(format))
        value = struct.unpack(format, buffer)
        return value[0] if len(value) == 1 else value
