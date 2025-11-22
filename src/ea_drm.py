import pathlib
import struct
import base64
from dataclasses import dataclass

import pefile
from Crypto.Cipher import AES
from Crypto.Util import Padding


LICENSE_KEY = base64.b64decode("QTJyLdCC77DcZFfFdmjKCQ==")

# TODO: move these constants to a config file (or try to compute the offsets?)
KEY = bytes(16)
ENCRYPTED_SECTIONS_TABLE_OFFSET = 0x0


@dataclass
class EncryptedSection:
    rva: int
    encrypted_size: int
    decrypted_size: int
    padding: bytes


class EA_DRM:

    def __init__(self, license_path: str, pe_path: str):
        self._license_path = pathlib.Path(license_path)
        self._decryption_key = bytes()
        self._pe_path = pathlib.Path(pe_path)
        self._pe = pefile.PE(pe_path, fast_load=True)


    def retrieve_decryption_key(self) -> None:
        with open(self._license_path, 'rb') as license_file:
            license_file.seek(0x41)
            encrypted_license = license_file.read()        
        decrypted_license = EA_DRM._aes_decrypt(LICENSE_KEY, encrypted_license).decode('utf-8')
        # TODO: update decryption key

    
    def decrypt_sections(self):
        count = self._read_pe(ENCRYPTED_SECTIONS_TABLE_OFFSET, 'B')
        for i in range(count):
            offset = ENCRYPTED_SECTIONS_TABLE_OFFSET + 0x1 + i * 0x30
            encrypted_section = EncryptedSection(
                rva=self._read_pe(offset + 0x0, '<L'),
                encrypted_size=self._read_pe(offset + 0x4, '<L'),
                decrypted_size=self._read_pe(offset + 0x8, '<L'),
                padding=self._read_pe(offset + 0x20, '16B'),
            )
            self._decrypt_section(encrypted_section)


    def _decrypt_section(self, encrypted_section: EncryptedSection) -> None:
        encrypted_data = self._pe.get_data(encrypted_section.rva, encrypted_section.encrypted_size)
        assert len(encrypted_data) == encrypted_section.encrypted_size
        
        decrypted_data = EA_DRM._aes_decrypt(self._decryption_key, encrypted_data)
        assert len(decrypted_data) == encrypted_section.decrypted_size
        
        padding = bytearray(16)
        for i in range(16):
            padding[i] = (decrypted_data[encrypted_section.decrypted_size - 0x10 + i] + 0x14) ^ encrypted_section.padding[i]

        self._pe.set_bytes_at_rva(encrypted_section.rva, decrypted_data + padding)

    
    def _read_pe(self, offset: int, format: str):
        rva = self._pe.get_rva_from_offset(offset)
        buffer = self._pe.get_data(rva, struct.calcsize(format))
        value = struct.unpack(format, buffer)
        return value[0] if len(value) == 1 else value
    

    @staticmethod
    def _aes_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
        aes = AES.new(key=key, mode=AES.MODE_CBC, iv=bytes(16))
        decrypted_data = Padding.unpad(aes.decrypt(encrypted_data), AES.block_size)
        return decrypted_data
